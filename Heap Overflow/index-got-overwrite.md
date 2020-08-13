# Using array indexing to overwrite a GOT entry


### What is this?

Consider the following example:-

```C
-- snip -- 

int some_array[100];

index = read(0, buf, 32);
index = atoi(buf);
data = read(0, name, 0x80);
if(data)
{
    some_array[index] = data;
}
```

This seems quite correct at some extent but the problem you can is we can specify  any **negative** integer which will somehow try to read from the nearby memory areas and try to print it.

Let's say, our input test cases would be