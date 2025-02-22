import ctypes
import os

# Define the AllocatedMemory structure in Python (MUST be done FIRST)
class AllocatedMemory(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("size", ctypes.c_size_t)]


# Now define the AllocatedMemoryWrapper class (can be done next)
class AllocatedMemoryWrapper:  # Renamed to avoid name clash
    def __init__(self, size):
        self._mem = lib.allocate_memory(size)
        if not self._mem:
            raise MemoryError("Allocation failed")
        self.size = size
        self.buffer = (ctypes.c_uint8 * size).from_address(self._mem.contents.data)

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            start, stop, step = key.start or 0, key.stop or self.size, key.step or 1
            indices = range(start, stop, step)
            value_list = list(value) if isinstance(value, (bytes, list)) else [value] * len(indices)

            for i, val in enumerate(value_list):
                try:
                    index = indices[i]
                    if 0 <= index < self.size:
                        self.buffer[index] = ctypes.c_ubyte(val)
                except IndexError:  # Value list shorter than indices
                    break

        elif isinstance(key, int):
            if 0 <= key < self.size:
                self.buffer[key] = ctypes.c_ubyte(value)
            else:
                raise IndexError("Index out of bounds")
        else:
            raise TypeError("Key must be an integer or slice")

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.start or 0, key.stop or self.size, key.step or 1
            return bytes(self.buffer[start:stop:step])

        elif isinstance(key, int):
            if 0 <= key < self.size:
                return self.buffer[key]
            else:
                raise IndexError("Index out of bounds")
        else:
            raise TypeError("Key must be an integer or slice")

    def free(self):
        lib.free_memory(self._mem)
        self._mem = None
        self.size = 0

    def __del__(self):
        if self._mem:
            self.free()
        
    def __enter__(self):
        return self
    
    def __exit__(self, *a):
        if self._mem:
            self.free()


# Load the C library
try:
    lib = ctypes.CDLL("./libmemory.so")  # Linux/macOS
except OSError:
    lib = ctypes.CDLL("./memory.dll")  # Windows

# Define argtypes and restypes
lib.allocate_memory.argtypes = [ctypes.c_size_t]
lib.allocate_memory.restype = ctypes.POINTER(AllocatedMemory)

lib.free_memory.argtypes = [ctypes.POINTER(AllocatedMemory)]
lib.free_memory.restype = None

lib.get_byte.argtypes = [ctypes.POINTER(AllocatedMemory), ctypes.c_size_t]
lib.get_byte.restype = ctypes.c_uint8

lib.set_byte.argtypes = [ctypes.POINTER(AllocatedMemory), ctypes.c_size_t, ctypes.c_uint8]
lib.set_byte.restype = None

def ttest(mem):
    mem[:4] = b'blah'

def test_memory():
    try:
        with AllocatedMemoryWrapper(2048) as mem:  # Use the wrapper class
            mem[:12] = b'Hello world!'
            assert mem[4] == ord('o')

            mem[20] = 0x08
            assert mem[20] == 0x08

            mem[100:110] = b"test_slice"
            assert mem[100:110] == b"test_slice"

            mem[200:210:2] = [97, 98, 99, 100, 101]
            assert mem[200:210:2] == b"abcde"

            mem[300:310:2] = 120
            assert mem[300] == 120
            assert mem[302] == 120
            assert mem[304] == 120
            assert mem[306] == 120
            assert mem[308] == 120

            threading.Thread(target=lambda: ttest(mem)).start()
            time.sleep(1)

            print(mem[:4])

            #mem.free()
        print("All tests passed!")
        print(mem._mem, '<- if None, success!!')

    except Exception as e:
        print(f"Error: {e}")
        raise


if __name__ == "__main__":
    import threading, time
    test_memory()