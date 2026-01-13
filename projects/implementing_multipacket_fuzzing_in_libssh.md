
# Implementing multipacket fuzzing

I looked at the libssh fuzzers and as it turns out, all of them are basically just single packet fuzzers. They take a single packet, and process it, then quit. This is a pain in the ass when trying to fuzz sftp for example...

## Implementing packet cutting.

Let's take this example from my fuzzing harness which I have wrote up:

{% raw %}
```

        do {


            /*

nwritten = send(socket_fds[1], data, size, 0);
    assert((size_t)nwritten == size);

    rc = shutdown(socket_fds[1], SHUT_WR);
    assert(rc == 0);

            */




            nwritten = send(socket_fds[1], data, size, 0);
            assert((size_t)nwritten == size);








            fprintf(stderr, "%s\n", "eeeeeeeeeeee");
            fprintf(stderr, "packet_count == %d\n", packet_count);

            //abort();
            size_t n = 0;
            while (sdata.authenticated == false || sdata.channel == NULL) {
                if (sdata.auth_attempts >= 3 || n >= 100) {
                    break;
                }

                if (ssh_event_dopoll(event, -1) == SSH_ERROR) {
                    break;
                }

                n++;
            }

            packet_count += 1;

        } while (ssh_channel_is_open(sdata.channel));

```
{% endraw %}

(this code is based on the ssh_server_fuzzer.c source code originally)...

I found this quick stackoverflow post: https://stackoverflow.com/a/1541821/14577985 and I decided to use some of this code as inspiration...

actually this seems to be sufficient:

{% raw %}
```

            byte *p = memmem(buf_pointer, lSize, needle, 4);
            if (!p) {
                packet_size = lSize; // The size of this packet is the leftover size...
                final_cycle = 1;
            } else {

                packet_size = (p - buf_pointer); // The size is the address of the next packet - address of the original pointer.
                lSize -= (p + sizeof(needle)) - buf_pointer;
            };














            nwritten = send(socket_fds[1], data, size, 0);
            assert((size_t)nwritten == size);


            fprintf(stderr, "%s\n", "eeeeeeeeeeee");
            fprintf(stderr, "packet_count == %d\n", packet_count);

            //abort();
            size_t n = 0;
            while (sdata.authenticated == false || sdata.channel == NULL) {
                if (sdata.auth_attempts >= 3 || n >= 100) {
                    break;
                }

                if (ssh_event_dopoll(event, -1) == SSH_ERROR) {
                    break;
                }

                n++;
            }

            packet_count += 1;



            if (final_cycle) {
                break;
            }

            buf_pointer = (p) + sizeof(needle); // Skip over to the next buffer





        } while (ssh_channel_is_open(sdata.channel));

```
{% endraw %}

I added these to the start:

{% raw %}
```

    byte needle[4] = {0x41, 0x41, 0x41, 0x41};
    byte *last_needle = NULL;
    int final_cycle = 0; // This is to indicate that the current iteration is the very last.
    int packet_size = 0;


```
{% endraw %}
















