import numpy as np


class HenonMap:
  size = 25.0
  __a: float
  __b: float
  __c: float

  def __init__(self, a, b, c, size=18.54) -> None:
    self.__a = a % size
    self.__b = b % size
    self.__c = c % size

  def __str__(self) -> str:
    return f"({self.__a}, {self.__b}, {self.__c})"
  
  def __eq__(self, __value: object) -> bool:
    if isinstance(__value, tuple) and len(__value) == 3:
        return __value[0] == self.__a and __value[1] == self.__b and __value[2] == self.__c

    if not isinstance(__value, HenonMap):
      return False

    return __value.__a == self.__a and __value.__b == self.__b and __value.__c == self.__c

  def next(self):
    new_a = (1.76 - self.__b ** 2 - 0.1 * self.__c)
    new_b = self.__a
    new_c = self.__b

    new_a %= self.size

    return HenonMap(new_a, new_b, new_c)

  def get_tuple(self):
    return (self.__a, self.__b, self.__c)
  
  def copy(self):
    return HenonMap(self.__a, self.__b, self.__c)
  
class ThomasAttractorMap:
  __a: float
  __b: float
  __c: float

  def __init__(self, a, b, c) -> None:
    self.__a = a
    self.__b = b
    self.__c = c

  def __str__(self) -> str:
    return f"({self.__a}, {self.__b}, {self.__c})"
  
  def __eq__(self, __value: object) -> bool:
    if isinstance(__value, tuple) and len(__value) == 3:
        return __value[0] == self.__a and __value[1] == self.__b and __value[2] == self.__c

    if not isinstance(__value, ThomasAttractorMap):
      return False

    return __value.__a == self.__a and __value.__b == self.__b and __value.__c == self.__c

  
  def next(self):
    B_CONST = 0.208186

    new_a = np.sin(self.__b) - B_CONST * self.__a
    new_b = np.sin(self.__c) - B_CONST * self.__b
    new_c = np.sin(self.__a) - B_CONST * self.__c

    return ThomasAttractorMap(new_a, new_b, new_c)

  def get_tuple(self):
    return (self.__a, self.__b, self.__c)
  
  
class LogisticMap:
  __a: float
  __b: float
  __c: float

  def __init__(self, a, b, c) -> None:
    self.__a = a
    self.__b = b
    self.__c = c

  def __str__(self) -> str:
    return f"({self.__a}, {self.__b}, {self.__c})"
  
  def __eq__(self, __value: object) -> bool:
    if isinstance(__value, tuple) and len(__value) == 3:
        return __value[0] == self.__a and __value[1] == self.__b and __value[2] == self.__c

    if not isinstance(__value, LogisticMap):
      return False

    return __value.__a == self.__a and __value.__b == self.__b and __value.__c == self.__c

  
  def next(self):
    R_CONST = 4

    new_a = R_CONST * self.__a * (1 - self.__a) 
    new_b = R_CONST * self.__b * (1 - self.__b) 
    new_c = R_CONST * self.__c * (1 - self.__c) 

    return LogisticMap(new_a, new_b, new_c)

  def get_tuple(self):
    return (self.__a, self.__b, self.__c)