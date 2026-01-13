# Fuzzing libsoup

## Motivation

This fuzzing attempt was largely motivated by this blog post here: https://offsec.almond.consulting/using-aflplusplus-on-bug-bounty-programs-an-example-with-gnome-libsoup.html so I decided to also take a crack at it...

## The usual setup...

Git clone https://gitlab.gnome.org/GNOME/libsoup.git and then compile this harness here:

{% raw %}
```
#include <libsoup/soup.h>

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
    SoupMessageHeaders  *req_headers;
    guint ret;
    GHashTable *params;
    req_headers = soup_message_headers_new(SOUP_MESSAGE_HEADERS_REQUEST);
    ret = soup_headers_parse_request((const char* )data,size,req_headers,NULL,NULL,NULL);
    if (ret == SOUP_STATUS_OK){
        soup_message_headers_get_content_type(req_headers, &params);

    }
    soup_message_headers_unref (req_headers);
    return 0;
}
```
{% endraw %}




