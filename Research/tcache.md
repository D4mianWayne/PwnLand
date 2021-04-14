# Tcache Mechanism Overview : GLIBC 2.27

GLIBC 2.27 introduced tcache bins which refer to thread cache mechanism for the heap allocation methods, the tcache bins are as of identical from the fastbins, the difference arisesas:

* The Tcache can store chunk of size < 0x410, while the fastbin can store the chunk of size < 0x7f.
* The tcache is based on the data structure as of the single linked list.
* A chunk of same size can be stored on the tcache for upto 7 times, being on the index where ther size of the chunk first fits to.

***

# GLIBC Source: Tcache

```C

#if USE_TCACHE
/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */
# define TCACHE_MAX_BINS		64
# define MAX_TCACHE_SIZE	tidx2usize (TCACHE_MAX_BINS-1)

/* Only used to pre-fill the tunables.  */
# define tidx2usize(idx)	(((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */

/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7
#endif
```

In here, the default size of tcache bin is 64, then the function `tidx2usize` is used to get the rounded size of a chunk depending on which index it is located to. Then the other bunch of utilities are defined, the alighment and rounding done on the size provided is then decide which chunk it belongs to. After that, the `TCACHE_FILL_COUNTS` is given the value 7, which refers to the number of free'd chunks **of the same size** would be stored, for example if we have 12 chunks of size between 0 - 24, and we free them, the first 7 free'd chunks would land into the tcache bins.

***

### Tcache Structure

The structure of the tcache bins is defined as:-

```C
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

The structure of the `tcache_entry`, there's a pointer to the next `tcache_entry` via `next` pointer, this implements the basic idea of a singly linked list. Then we have a `tcache_perthread_struct` which refers of the tcache struct and it is different for every thread, within the structure it defines the maximum number of bins the tcache is supposed to hold and then it creates the number of those linked list of type `tcache_entry`.

There are two functions which is used to retrieve and put the tcache bins in the heap which is defined by the `tcache_put` and `tcache_get` respectively.

```C
static __thread bool tcache_shutting_down = false;
static __thread tcache_perthread_struct *tcache = NULL;

tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

The `tcache_put` functionality is defined as:-

* First it resolves the address of the chunk and cast that chunk to the `tcache_entry` struct.
* It does an assertion check by checking the `tc_idx` of the chunk is below the `TCACHE_MAX_BINS`.
* Then the next pointer for the `e` is updated with the next entry from the `tcache_entries` for which the `idx` fits to.
* Then the `tcache_entries[tc_idx]` is assigned to the `tcache_entry`
* Then, for the `counts` which holds the number of bins in use is incremented.

This is how the chunk once free'd, put into the tcache bin. Now, we need to see how the chunnk, once again if requested from the `malloc` and if present in the tcache bin would be handled out to the program:-

```C
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```
The functionality of the `tcache_get` is defined as:-

* It retrieves the entry of the index defined from the `tcache`.
* Then it checks the assertion for the index and `TCACHE_MAX_BINS`.
* It then checks the assertion for the if the entries at the chunk is even valid.
* Update the next pointer for the `tcache` and then it decrements the count from the `tcache`.
* Then it returns the `e`.

***

# `malloc` & `free` in context of `tcache` bins

The `malloc`handles the chunks from the `tcache` bins as follows:-

```C
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
```
In case , if the `tcache` is enabled, it does some common checks for the size and on the basis of the size the index is retrieved, it then calls the `MAYBE_INIT_TCACHE` which is responsible for initializing the `tcache` mechanism, then it checks index is within the `tcache` bin size, if it does it makes a call to the `tcache_get(tc_idx)` and returns the chunk.

***

##### Handling of `fastbin`

```C
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (SINGLE_THREAD_P)
			*fb = tc_victim->fd;
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		    }
		}
#endif
```

The functionality is defined as:-
* Get the index where the chunk belongs to, then does the check for the `tcache` and the `tc_idx` for the tcache mechanism if it enabled or not.
* Then it makes a `tc_victim` chunk pointer, then it checks whether the bins for that specific index is already full or not.
* If npt, it checks for the single thread and when it does, it retrieves the `fd` of the `tc_victim->fd` and remove the fastbin chunk.
* Finally put the chunk in `tcache` where the chunk actually belongs to.

The above code handles how the functionality of the `fastbins` in respect to the `tcache`, first off it checks the `USE_TCACHE` if enabled, it then stashes the `fastbin` range of chunks into the `tcache` until the slot for that chunk is full, that means `tcache->entries[tc_idx]` value is 7, which is the default number of bins `tcache` entry for that specific index can hold.

 ***

##### Handling of `smallbin`

As similarly, the `fastbins` are handled, the stashing for the corresponding chunk is done as following:-

```C
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
```

The functionality of the above can be defined as:-
* The usual assertion checks for the index and the size is done.
* Then it gets the `bk` from the chunk and set the `prev_inuse` bit, this is true for all the free'd chunks residing into the `tcache`.
* Checks if the arena in which the chunk belongs to is main or not, depending on that it sets the arena flag.
* Stashes chunk into the tcache.

***

# Applicable Techniques of Tcache attack

* Tcache Poisoning
* Tcache Stashing Unlink
* Tcache House of Spirit
* Tcache dup


### Tcache Dup Mitigation

In the GLIBC-2.27ubuntu1.4, the double free mitigation towards the tcache chunks were introduced, the `tcache` structure became like:-

```C
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

Reference: <https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#tcache_perthread_struct>

In the `tcache_put` which is used to put the `free`'d chunks into the tcache bins, added a `key` member in the `tcache_entry` struct solely for the purpose of detecting the double free of the `tcache` chunks, when a chunk is `free`'d, `key` is initialized to the value of the `tcache`.

```C
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
        /* Check to see if it's already in the tcache.  */
        tcache_entry *e = (tcache_entry *) chunk2mem (p);
        /* This test succeeds on double free.  However, we don't 100%
           trust it (it also matches random payload data at a 1 in
           2^<size_t> chance), so verify it's not an unlikely
           coincidence before aborting.  */
        if (__glibc_unlikely (e->key == tcache))
          {
            tcache_entry *tmp;
            LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
            for (tmp = tcache->entries[tc_idx];
                 tmp;
                 tmp = tmp->next)
              if (tmp == e)
                malloc_printerr ("free(): double free detected in tcache 2");
            /* If we get here, it was a coincidence.  We've wasted a
               few cycles, but don't abort.  */
          }
        if (tcache->counts[tc_idx] < mp_.tcache_count)
          {
            tcache_put (p, tc_idx);
            return;
          }
      }
  }
#endif
```

In this, the `key` is checked whether it is equal to the `tcache`, then it is compared with the linked list of the `tcache` itself, the `key` will only be initialized once after the chunk is `free`'d and will be assigned to the `NULL` afterwards the chunk is requested again. So, if the `key` is as same as the `tcache`, then it traverse over the `tcache-entries` and compare the already `free`'d chunks with the one we `free`'d, if encountered it'll print the `free(): double free detected in tcache 2`.
