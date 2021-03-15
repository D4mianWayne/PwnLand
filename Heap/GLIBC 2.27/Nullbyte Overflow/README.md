# Nullbyte Overflow/Off by Null

This technique of the heap exploitation take advantage of the one byte overflow in the next chunk's `size` field, the one byte which will overflow would be the `\x00`, which will result in the `PREV_INUSE` bit defined in the size field being overwritten.


Before Null Byte Overflow:-

If we take example of a chunk being of size 0x100, then once it's allocated it will look like:-


```r
++++++++++++++++++++++++++++++++
|             |         0x91  |  <---  0x91, wherre 1 denotes the PREV_INUSE flag
++++++++++++++++++++++++++++++++
|                              |
|             AAAAA            |
|                              |
++++++++++++++++++++++++++++++++
|             |         0x101  |  <---  0x101, wherre 1 denotes the PREV_INUSE flag is enabled
++++++++++++++++++++++++++++++++
|                              |
|             BBBBB            |
|                              |
++++++++++++++++++++++++++++++++
```

Once we trigger Nullbyte Overflow, it'll become:-


```r
++++++++++++++++++++++++++++++++
|             |         0x91  |  <---  0x91, wherre 1 denotes the PREV_INUSE flag
++++++++++++++++++++++++++++++++
|                              |
|             AAAAA            |
|                              |
++++++++++++++++++++++++++++++++
|             |         0x100  |  <---  0x100, wherre  denotes the PREV_INUSE flag is disabled
++++++++++++++++++++++++++++++++
|                              |
|             BBBBB            |
|                              |
++++++++++++++++++++++++++++++++
```
> The `PREV_INUSE` flag is used by the GLIBC heap management to keep a track of contigous chunk, this bit is used to denote the chunks, stored right before the chunk we are referring to is in use and should be taken into consideration if they have to be merged together once `free` is called.

As shown in the how2heap repository created by the Shellphish. The [Overlapping Chunks]() shows a proof of concept work of this, using the same references shown, we can target binaries having Nullbyte Overflow.

```C
