##Writeup
**Reversing**

The program allowed the user (robot) to enter a bunch of information:
* name (max input length 255)
* encryption method (either 0, 1 or 2)
* location (max input length 255)
* goal (max input length 255)
* last words (max input length 255)

The information was put into a structure on the heap that looked something like this:
```
struct userinfo{
	char name[260];
	char goal[204];
	char *location;
}
```

The location input was put on the heap, and a pointer to it was put in the userinfo struct.

The 3 encryption method choices (0,1,2) corresponded to 3 different functions in the program, "0" was no encryption, "1" was xor with "A", "2" was xor with "x". These were used on any information sent back to the client. The encryption_function_choice function pointer was put on the heap.

Lastly, the "last words" were also put on the heap.

**Analysing**

Something that looked strange was that ```free(userinfo->location)``` was in the middle of the function (as opposed to at the end, like the other malloc()d stuff). This was indeed the key to the challenge.

By simply using a "goal" larger than 204 bytes, we can overwrite the *location pointer, and when the program reaches ```free(userinfo->location)```, we can use it to free(anything).

I used that to ```free(encryption_function_choice)```. This meant that the next time something of the same size would be allocated, malloc() would return the pointer to the encryption choice.

So I chose my "last words", carefully, to overwrite the encryption_function_choice pointer. When the program then tries to ```encryption_function_choice(userinfo->name)```, we get control over RIP (and first arg, RDI).

**ROP**

First off, I needed a stack shift so that I could ROP properly. I found this gadget to do so:
```
xchg rsp, rdi;
ret;
```

Great, we got stack control (since RDI pointed to userinfo->name). But also not great, because now we don't have RDI control any more. That didn't matter so much because we could control function arguments 1 (RDI) and 2 (RSI) with the following gadgets:
```
pop rdi;
ret;
```
```
pop rsi;
pop r15;
ret;
```

Now, we needed to leak a libc address somehow to be able to ret2libc. I did this by setting RDI (first arg) to 4 (filedescriptor number of our socket), RSI (second arg) to GOT and then returning to a part of the function that called send().

After that, we could calculate offset to libc base and from libc base to system(). The offsets were the same as the "baby" chall, so no need to guess libc version/leak/brute.

Then we could just use all of the ingredients mentioned to system("/bin/sh").

But that was a bit problematic. Because this chall (just like baby chall) didn't forward stdin/stdout to the socket, we first had to ```dup2(socket, stdin)``` and ```dup2(socket, stdout)```.

After that everything worked fine and shell aquired :)
```
leaking heap pointer...
leaking GOT...
libc:    0x0000f738659a0d00
system:  0x0000f73865ea3209
bin_sh:  0x0000f738652c1977
dup2:    0x0000f738659bd309
> cat flag
INS{RealWorldFlawsAreTheBest}
```
