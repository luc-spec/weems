class RewardFunction:
    def __init__(self):
        self.reputation_service = ReputationService()
        self.behavior_analyzer = BehaviorAnalyzer()

    def calculate_reward(self, state, action, outcome):
        # Get reputation scores
        app_reputation = self.reputation_service.get_app_reputation(
            state["process_path"]
        )
        dest_reputation = self.reputation_service.get_dest_reputation(
            state["destination_host"]
        )

        # Analyze behavior
        behavior_score = self.behavior_analyzer.analyze(state)

        # Base reward values
        allowed_malicious_penalty = -10.0
        blocked_legitimate_penalty = -1.0
        allowed_legitimate_reward = 1.0
        blocked_suspicious_reward = 0.5
        user_interruption_penalty = -0.2

        # Calculate final reward
        if action in [Actions.ALLOW_ONCE, Actions.ALLOW_TEMP, Actions.ALLOW_PERM]:
            # Allowed connection
            if dest_reputation < 0.3:  # Suspicious or malicious
                return allowed_malicious_penalty * (1 - dest_reputation) * 2
            else:  # Legitimate
                return allowed_legitimate_reward * app_reputation * dest_reputation
        else:
            # Blocked connection
            if dest_reputation > 0.7:  # Likely legitimate
                return blocked_legitimate_penalty * dest_reputation
            else:  # Suspicious
                return blocked_suspicious_reward * (1 - dest_reputation)

        # Penalty for requiring user input
        if action == Actions.ASK_USER:
            return user_interruption_penalty


class RLDecisionEngine:
    def __init__(self, model_path=None):
        self.model = DRQN(state_dim=STATE_DIM, action_dim=ACTION_DIM)
        if model_path and os.path.exists(model_path):
            self.model.load_weights(model_path)

        self.exploration_strategy = ThompsonSampling()
        self.experience_buffer = PrioritizedReplayBuffer(capacity=10000)

    def decide(self, state):
        # Get Q-values for all actions
        q_values = self.model.predict(state)

        # Apply exploration strategy
        action = self.exploration_strategy.select_action(q_values, state)

        # Map to OpenSnitch rule
        rule = self.action_to_rule(action, state)

        return rule, action

    def update(self, state, action, reward, next_state, done):
        # Store experience
        self.experience_buffer.add(state, action, reward, next_state, done)

        # Periodically train model
        if self.experience_buffer.is_ready_for_training():
            self.train()

    def train(self):
        # Sample batch from experience buffer
        batch = self.experience_buffer.sample(batch_size=64)

        # Update model weights using Q-learning
        loss = self.model.train_on_batch(batch)

        return loss
