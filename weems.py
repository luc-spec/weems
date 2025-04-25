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
  '''
  StateSpace: FIFO list of allow and block list tuples 
  '''
  _history: list[State]

  def __init__(self, history_length: int = 10000):
    self._max_len = history_length

  def current(self):
    '''
    Get the most recent allow/block lists
    '''
    return self._history[0]

  def history(self):
    '''
    Get the full history of state space
    '''
    return self._history

  def add(self, s:State):
    '''
    Add a State to the 0 index of our history
    '''
    self._history.insert(State)

  def remove(self):
    '''
    With no arguments, just remove our last entry
    '''
    self._history.pop(0)

  def remove(self, url: str):
    '''
    If we have a url argument, then make a new history entry
    with that url removed
    '''
    for entry in self._history:
      if url in entry.blocked:
        self._history.remove(entry)

def main():
  print("TODO")

if __name__ == "__main__":
  main()
