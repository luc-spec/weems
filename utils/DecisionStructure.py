from collections import namedtuple

# Define the action space
class Actions:
    ALLOW_ONCE = 0
    ALLOW_TEMP = 1  # Until application quits
    ALLOW_PERM = 2  # Always
    BLOCK_ONCE = 3
    BLOCK_TEMP = 4  # Until application quits
    BLOCK_PERM = 5  # Always
    ASK_USER = 6    # Request user input

    @staticmethod
    def to_str(action: int) -> str:
        return {
            Actions.ALLOW_ONCE: "Allow Once",
            Actions.ALLOW_TEMP: "Allow Until Quit",
            Actions.ALLOW_PERM: "Allow Always",
            Actions.BLOCK_ONCE: "Block Once",
            Actions.BLOCK_TEMP: "Block Until Quit",
            Actions.BLOCK_PERM: "Block Always",
            Actions.ASK_USER: "Ask User",
        }.get(action, "Unknown")
    
    @staticmethod
    def count() -> int:
        return 7  # Number of possible actions
    

# Experience buffer for reinforcement learning
Experience = namedtuple(
    'Experience', 
    ['state', 'action', 'reward', 'next_state', 'done']
)