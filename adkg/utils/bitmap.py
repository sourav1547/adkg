class Bitmap:
    def __init__(self, len, x=None):
        self.BYTES_LENGTH = len//8 + len%8
        if len<8:
            self.BYTES_LENGTH = 1   
        
        self.array = x
        if x is None:
            self.array = bytearray(self.BYTES_LENGTH)
            
    
    def set_bit(self, index):
        assert(index < self.BYTES_LENGTH * 8)
        bucket = index // 8
        bucket_pos = index - (bucket * 8)
        self.array[bucket] |= 128 >> bucket_pos
    
    def get_bit(self, index) -> bool:
        assert(index < self.BYTES_LENGTH * 8)
        bucket = index // 8
        bucket_pos = index - (bucket * 8)
        return (self.array[bucket] & (128 >> bucket_pos)) != 0

if __name__ == "__main__":
    import random
    x = Bitmap(128)
    for i in range(128):
        if random.randint(1,2) ==1:
            x.set_bit(i)
    y = Bitmap(128, x.array)
    print(x.array)
    print(y.array)
    print(x.get_bit(12))
    print(y.get_bit(0))
    y.set_bit(0)
    print(y.get_bit(0))
    print(x.get_bit(0))