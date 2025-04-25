'''

Weems

  An adaptive network filter service.

'''
from dataclasses import dataclass

@dataclass
class State:
  '''Data structure for keeping track of allow/block states'''
  allowed: tuple[str]
  blocked: tuple[str]

@dataclass
class StateSpace:
  history: tuple[State] 

def main():
  printf("TODO")

if __name__ == "__main__":
  main()
