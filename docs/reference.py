# Independent reference implementation of docs/SPEC.md v1 (needs: pip install argon2-cffi).
# Prints the same values pinned in tests/vectors.rs.

import hashlib, hmac, struct, unicodedata
from argon2.low_level import hash_secret_raw, Type
L=b"abcdefghijklmnopqrstuvwxyz"; U=L.upper(); D=b"0123456789"; SY=b"!#$%&()*+,-./:;<=>?@[]^_{|}~"
def hkdf(salt, ikm, info, n=32):
    prk=hmac.new(salt, ikm, hashlib.sha256).digest(); t=b""; out=b""; i=1
    while len(out)<n: t=hmac.new(prk,t+info+bytes([i]),hashlib.sha256).digest(); out+=t; i+=1
    return out[:n]
WORDS=['acorn', 'album', 'alien', 'amber', 'anchor', 'apple', 'apron', 'arrow', 'atlas', 'attic', 'badge', 'bagel', 'bamboo', 'banjo', 'barrel', 'basil', 'basket', 'beach', 'beacon', 'beaver', 'berry', 'bison', 'blade', 'blanket', 'blossom', 'bonsai', 'bottle', 'brick', 'bridge', 'broom', 'bubble', 'bucket', 'buffalo', 'bugle', 'button', 'cabin', 'cactus', 'camel', 'candle', 'canoe', 'canyon', 'carpet', 'carrot', 'castle', 'cedar', 'cello', 'cherry', 'chess', 'chimney', 'cider', 'circus', 'citrus', 'cliff', 'cloud', 'clover', 'cobra', 'coconut', 'comet', 'compass', 'copper', 'coral', 'cotton', 'coyote', 'crane', 'crayon', 'cricket', 'crown', 'crystal', 'cupcake', 'curtain', 'daisy', 'desert', 'diamond', 'dingo', 'dolphin', 'domino', 'donkey', 'dragon', 'drum', 'eagle', 'easel', 'echo', 'eclipse', 'ember', 'emerald', 'engine', 'falcon', 'feather', 'fern', 'ferret', 'fiddle', 'fig', 'flame', 'flute', 'forest', 'fossil', 'fountain', 'fox', 'frost', 'galaxy', 'garden', 'garlic', 'gecko', 'geyser', 'ginger', 'giraffe', 'glacier', 'globe', 'goblet', 'gopher', 'grape', 'gravel', 'guitar', 'hammer', 'harbor', 'harp', 'hazel', 'hedge', 'helmet', 'heron', 'hippo', 'honey', 'hornet', 'husky', 'igloo', 'iris', 'island', 'ivory', 'jacket', 'jaguar', 'jasmine', 'jelly', 'jewel', 'jungle', 'kayak', 'kettle', 'kiwi', 'koala', 'ladder', 'lagoon', 'lantern', 'lemon', 'lettuce', 'lily', 'lion', 'lizard', 'llama', 'lobster', 'locket', 'lotus', 'magnet', 'mango', 'maple', 'marble', 'meadow', 'melon', 'meteor', 'mint', 'mirror', 'mitten', 'monkey', 'moose', 'mosaic', 'muffin', 'mushroom', 'napkin', 'nectar', 'needle', 'noodle', 'nutmeg', 'oasis', 'ocean', 'olive', 'onion', 'orbit', 'orchid', 'otter', 'oyster', 'paddle', 'panda', 'papaya', 'parrot', 'peach', 'peanut', 'pebble', 'pelican', 'pepper', 'piano', 'pickle', 'pigeon', 'pillow', 'pine', 'pirate', 'planet', 'plum', 'pony', 'poppy', 'potato', 'pretzel', 'puffin', 'pumpkin', 'puzzle', 'quartz', 'quill', 'rabbit', 'radish', 'raven', 'reef', 'ribbon', 'river', 'robin', 'rocket', 'rose', 'ruby', 'saddle', 'salmon', 'sandal', 'saturn', 'scarf', 'seal', 'shell', 'silver', 'sloth', 'snail', 'spider', 'sponge', 'spruce', 'squid', 'statue', 'storm', 'sugar', 'summit', 'sunset', 'swan', 'teapot', 'tiger', 'tomato', 'topaz', 'torch', 'tulip', 'tundra', 'turtle', 'umbrella', 'valley', 'velvet', 'violin', 'volcano', 'wagon', 'walnut', 'walrus', 'whale', 'willow', 'wizard', 'yacht', 'zebra', 'zephyr']

def check_code(secret,salt):
    m=hash_secret_raw(secret.encode(),salt,time_cost=3,memory_cost=65536,parallelism=1,hash_len=32,type=Type.ID,version=19)
    return "-".join(WORDS[b] for b in hkdf(b"CodePass/HKDF/v1",m,b"CodePass/check-code/v1",3))

def gen(secret,salt,src,site,acct,length,cs,rev,req):
    h=hashlib.sha256(src).digest()
    m=hash_secret_raw(secret.encode(),salt,time_cost=3,memory_cost=65536,parallelism=1,hash_len=32,type=Type.ID,version=19)
    ctx=b"CodePass/context/v1\0"+h
    for s in (site,acct):
        b=unicodedata.normalize("NFC",s).encode(); ctx+=struct.pack(">I",len(b))+b
    ctx+=struct.pack(">I",rev)+bytes([length,1 if cs=="strong" else 2,int(req)])
    k=hkdf(b"CodePass/HKDF/v1",m,ctx)
    a=L+U+D+(SY if cs=="strong" else b""); lim=256//len(a)*len(a)
    def stream():
        i=0
        while True:
            yield from hmac.new(k,b"CodePass/stream/v1\0"+struct.pack(">Q",i),hashlib.sha256).digest(); i+=1
    st=stream()
    while True:
        c=bytearray()
        while len(c)<length:
            b=next(st)
            if b<lim: c.append(a[b%len(a)])
        ok=all(any(x in cl for x in c) for cl in ([L,U,D]+([SY] if cs=="strong" else [])))
        if not req or ok: return c.decode()
src=b'fn main() {\n    println!("hello");\n}\n'; sec="correct horse battery staple 2026"; salt=b"CodePassTestSalt"
for args in [("github.com","",24,"strong",1,True),("github.com","personal",24,"strong",2,True),("example.com","",8,"alnum",1,True),("café.example","ゆうた",64,"strong",1,False)]:
    print("VECTOR", args[0], gen(sec,salt,src,*args))
print("CHECK", check_code(sec,salt))
