
# Making a tool to find hangs in python3

I recently found a denial of service vulnerability in a piece of software. Here is the link to the bug: https://github.com/django/django/commit/d6664574539c1531612dea833d264ed5c2b04e1e . It basically consists of a lot of opening a lot of opening braces and a lot of closing braces. This causes denial of service, when that input is passed to the urlize or urlizetrunc filters.

## Motivation

I initially found the bug by just reading the source code and noticed that something didn't add up. The funny thing is that this same function was actually fuzzed using a fuzzer already, but that fuzzer was a traditional fuzzer. DOS bugs which are based on user input are usually caused by repeated input of some kind. (repeating the same input string many times). I think that we should implement a custom mutator library and then try to rediscover this bug.

## Starting the custom mutator build

Ok, so let's look up atheris (a libfuzzer based fuzzer for python programs): https://github.com/google/atheris

I would prefer to write a custom mutator in python, because that is the programming language which I am most proficient in, but atheris is libfuzzer based and libfuzzer only supports writing custom mutators in C-code . Wait... after a bit of reading through the code, it seems that there is a python custom mutator.

Now, the bug which I found was caused by a very long input, so therefore we want to increase the max payload size with `-max_len=500000` in the atheris command line. (The default maximum length is 4069 which may miss some dos cases with very large inputs.) .

Ok, so let's create a github repo to mutate ascii strings in this way.

Here is my github repository: https://github.com/personnumber3377/dos_finder

## Figuring out fuzzing strategies

Ok, so I think I want to create a couple of strategies:

1. Create a completely new string (discard the original data)
2. Modify a string by adding or removing a certain string and multiplying it many times over...

Let's just implement strategy 1 first (aka generate entirely new strings). I think that there is a requirement for the fuzzer to be deterministic, but I don't know the truth about that. Done!

Ok, so now let's create strategy number 2... Done!

I now have a mutator which repeats strings, because repeated strings are usually a cause for a dos thing and stuff like that.

You can get the custom mutator from here: https://github.com/personnumber3377/dos_finder

## Testing out our new tool

Does it find the bug? Let's see... yes! It can find the bug!!! This is good!

Let's try to fuzz let's say.. the multipartparser in django? Now looking at the source code, it seems that there is no good parser method, which just accepts the content as is

## Making a fuzzing harness

Ok, so now let's just program a fuzzing harness:

Here is the method which parses the multipart request:

```

    def parse_file_upload(self, META, post_data):
        """Return a tuple of (POST QueryDict, FILES MultiValueDict)."""
        self.upload_handlers = ImmutableList(
            self.upload_handlers,
            warning=(
                "You cannot alter upload handlers after the upload has been "
                "processed."
            ),
        )
        parser = MultiPartParser(META, post_data, self.upload_handlers, self.encoding)
        return parser.parse()

```

and seems quite a nice little function...

let's create an instance of the `class HttpRequest:` class and then try to call parse_file_upload on that...

something like this:

```


from django.http.request import *
from django.conf import settings
from io import BytesIO # For making a bytearray to a file handle type thing

# class HttpRequest:




if __name__=="__main__":

	settings.configure()

	req = HttpRequest() # Create the object.
	meta_shit = {} # Empty metadata for now.
	data = b"" # Empty data for now.
	data = BytesIO(data)


	# meta_shit = {'SHELL': '/usr/bin/bash', 'SESSION_MANAGER': 'local/oof-h8-1440eo:@/tmp/.ICE-unix/1294,unix/oof-h8-1440eo:/tmp/.ICE-unix/1294', 'QT_ACCESSIBILITY': '1', 'COLORTERM': 'truecolor', 'XDG_CONFIG_DIRS': '/etc/xdg/xdg-cinnamon:/etc/xdg', 'XDG_SESSION_PATH': '/org/freedesktop/DisplayManager/Session0', 'NVM_INC': '/home/oof/.nvm/versions/node/v18.17.0/include/node', 'GNOME_DESKTOP_SESSION_ID': 'this-is-deprecated', 'LANGUAGE': 'en_US', 'TERMINATOR_DBUS_PATH': '/net/tenshu/Terminator2', 'LC_ADDRESS': 'fi_FI.UTF-8', 'LC_NAME': 'fi_FI.UTF-8', 'SSH_AUTH_SOCK': '/run/user/1000/keyring/ssh', 'CINNAMON_VERSION': '5.4.12', 'TERMINATOR_UUID': 'urn:uuid:dcf7087a-c448-4268-93e9-95099a2ac52f', 'DESKTOP_SESSION': 'cinnamon', 'LC_MONETARY': 'fi_FI.UTF-8', 'GTK_MODULES': 'gail:atk-bridge', 'XDG_SEAT': 'seat0', 'PWD': '/home/oof/django/fileupload/minimal-django-file-upload-example/src/for_django_3-0', 'LOGNAME': 'oof', 'XDG_SESSION_DESKTOP': 'cinnamon', 'QT_QPA_PLATFORMTHEME': 'qt5ct', 'XDG_SESSION_TYPE': 'x11', 'GPG_AGENT_INFO': '/run/user/1000/gnupg/S.gpg-agent:0:1', 'XAUTHORITY': '/home/oof/.Xauthority', 'XDG_GREETER_DATA_DIR': '/var/lib/lightdm-data/oof', 'GJS_DEBUG_TOPICS': 'JS ERROR;JS LOG', 'GDM_LANG': 'en_US', 'HOME': '/home/oof', 'LC_PAPER': 'fi_FI.UTF-8', 'LANG': 'en_US.UTF-8', 'LS_COLORS': 'rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:', 'XDG_CURRENT_DESKTOP': 'X-Cinnamon', 'VTE_VERSION': '6800', 'XDG_SEAT_PATH': '/org/freedesktop/DisplayManager/Seat0', 'TERMINATOR_DBUS_NAME': 'net.tenshu.Terminator21a9d5db22c73a993ff0b42f64b396873', 'GJS_DEBUG_OUTPUT': 'stderr', 'NVM_DIR': '/home/oof/.nvm', 'LESSCLOSE': '/usr/bin/lesspipe %s %s', 'XDG_SESSION_CLASS': 'user', 'TERM': 'xterm-256color', 'LC_IDENTIFICATION': 'fi_FI.UTF-8', 'GTK_OVERLAY_SCROLLING': '1', 'LESSOPEN': '| /usr/bin/lesspipe %s', 'USER': 'oof', 'DISPLAY': ':0', 'SHLVL': '1', 'NVM_CD_FLAGS': '', 'LC_TELEPHONE': 'fi_FI.UTF-8', 'LC_MEASUREMENT': 'fi_FI.UTF-8', 'XDG_VTNR': '7', 'XDG_SESSION_ID': 'c1', 'XDG_RUNTIME_DIR': '/run/user/1000', 'GTK3_MODULES': 'xapp-gtk3-module', 'XDG_DATA_DIRS': '/usr/share/cinnamon:/usr/share/gnome:/home/oof/.local/share/flatpak/exports/share:/var/lib/flatpak/exports/share:/usr/local/share:/usr/share', 'PATH': '/home/oof/.nvm/versions/node/v18.17.0/bin:/home/oof/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin', 'GDMSESSION': 'cinnamon', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1000/bus', 'NVM_BIN': '/home/oof/.nvm/versions/node/v18.17.0/bin', 'GIO_LAUNCHED_DESKTOP_FILE_PID': '2335', 'GIO_LAUNCHED_DESKTOP_FILE': '/usr/share/applications/terminator.desktop', 'LC_NUMERIC': 'fi_FI.UTF-8', '_': '/usr/bin/python3', 'OLDPWD': '/home/oof/django/fileupload/minimal-django-file-upload-example/src', 'DJANGO_SETTINGS_MODULE': 'myproject.settings', 'TZ': 'UTC', 'RUN_MAIN': 'true', 'SERVER_NAME': 'localhost', 'GATEWAY_INTERFACE': 'CGI/1.1', 'SERVER_PORT': '8000', 'REMOTE_HOST': '', 'CONTENT_LENGTH': '2942692', 'SCRIPT_NAME': '', 'SERVER_PROTOCOL': 'HTTP/1.1', 'SERVER_SOFTWARE': 'WSGIServer/0.2', 'REQUEST_METHOD': 'POST', 'PATH_INFO': '/', 'QUERY_STRING': '', 'REMOTE_ADDR': '127.0.0.1', 'CONTENT_TYPE': 'multipart/form-data; boundary=----WebKitFormBoundaryzDqFUPB4gF0buimW', 'HTTP_HOST': '127.0.0.1:8000', 'HTTP_CONNECTION': 'keep-alive', 'HTTP_CACHE_CONTROL': 'max-age=0', 'HTTP_SEC_CH_UA': '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"', 'HTTP_SEC_CH_UA_MOBILE': '?0', 'HTTP_SEC_CH_UA_PLATFORM': '"Linux"', 'HTTP_UPGRADE_INSECURE_REQUESTS': '1', 'HTTP_ORIGIN': 'http://127.0.0.1:8000', 'HTTP_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', 'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7', 'HTTP_SEC_FETCH_SITE': 'same-origin', 'HTTP_SEC_FETCH_MODE': 'navigate', 'HTTP_SEC_FETCH_USER': '?1', 'HTTP_SEC_FETCH_DEST': 'document', 'HTTP_REFERER': 'http://127.0.0.1:8000/', 'HTTP_ACCEPT_ENCODING': 'gzip, deflate, br, zstd', 'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.9', 'HTTP_COOKIE': 'csrftoken=w8pIBqNHLRogHrP3uUWW0OWY4sulqEOa', 'wsgi.input': <django.core.handlers.wsgi.LimitedStream object at 0x7f46d0934100>, 'wsgi.errors': <_io.TextIOWrapper name='<stderr>' mode='w' encoding='utf-8'>, 'wsgi.version': (1, 0), 'wsgi.run_once': False, 'wsgi.url_scheme': 'http', 'wsgi.multithread': True, 'wsgi.multiprocess': False, 'wsgi.file_wrapper': <class 'wsgiref.util.FileWrapper'>, 'CSRF_COOKIE': 'w8pIBqNHLRogHrP3uUWW0OWY4sulqEOa'}




	meta_shit = {'SHELL': '/usr/bin/bash', 'SESSION_MANAGER': 'local/oof-h8-1440eo:@/tmp/.ICE-unix/1294,unix/oof-h8-1440eo:/tmp/.ICE-unix/1294', 'QT_ACCESSIBILITY': '1', 'COLORTERM': 'truecolor', 'XDG_CONFIG_DIRS': '/etc/xdg/xdg-cinnamon:/etc/xdg', 'XDG_SESSION_PATH': '/org/freedesktop/DisplayManager/Session0', 'NVM_INC': '/home/oof/.nvm/versions/node/v18.17.0/include/node', 'GNOME_DESKTOP_SESSION_ID': 'this-is-deprecated', 'LANGUAGE': 'en_US', 'TERMINATOR_DBUS_PATH': '/net/tenshu/Terminator2', 'LC_ADDRESS': 'fi_FI.UTF-8', 'LC_NAME': 'fi_FI.UTF-8', 'SSH_AUTH_SOCK': '/run/user/1000/keyring/ssh', 'CINNAMON_VERSION': '5.4.12', 'TERMINATOR_UUID': 'urn:uuid:dcf7087a-c448-4268-93e9-95099a2ac52f', 'DESKTOP_SESSION': 'cinnamon', 'LC_MONETARY': 'fi_FI.UTF-8', 'GTK_MODULES': 'gail:atk-bridge', 'XDG_SEAT': 'seat0', 'PWD': '/home/oof/django/fileupload/minimal-django-file-upload-example/src/for_django_3-0', 'LOGNAME': 'oof', 'XDG_SESSION_DESKTOP': 'cinnamon', 'QT_QPA_PLATFORMTHEME': 'qt5ct', 'XDG_SESSION_TYPE': 'x11', 'GPG_AGENT_INFO': '/run/user/1000/gnupg/S.gpg-agent:0:1', 'XAUTHORITY': '/home/oof/.Xauthority', 'XDG_GREETER_DATA_DIR': '/var/lib/lightdm-data/oof', 'GJS_DEBUG_TOPICS': 'JS ERROR;JS LOG', 'GDM_LANG': 'en_US', 'HOME': '/home/oof', 'LC_PAPER': 'fi_FI.UTF-8', 'LANG': 'en_US.UTF-8', 'LS_COLORS': 'rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:', 'XDG_CURRENT_DESKTOP': 'X-Cinnamon', 'VTE_VERSION': '6800', 'XDG_SEAT_PATH': '/org/freedesktop/DisplayManager/Seat0', 'TERMINATOR_DBUS_NAME': 'net.tenshu.Terminator21a9d5db22c73a993ff0b42f64b396873', 'GJS_DEBUG_OUTPUT': 'stderr', 'NVM_DIR': '/home/oof/.nvm', 'LESSCLOSE': '/usr/bin/lesspipe %s %s', 'XDG_SESSION_CLASS': 'user', 'TERM': 'xterm-256color', 'LC_IDENTIFICATION': 'fi_FI.UTF-8', 'GTK_OVERLAY_SCROLLING': '1', 'LESSOPEN': '| /usr/bin/lesspipe %s', 'USER': 'oof', 'DISPLAY': ':0', 'SHLVL': '1', 'NVM_CD_FLAGS': '', 'LC_TELEPHONE': 'fi_FI.UTF-8', 'LC_MEASUREMENT': 'fi_FI.UTF-8', 'XDG_VTNR': '7', 'XDG_SESSION_ID': 'c1', 'XDG_RUNTIME_DIR': '/run/user/1000', 'GTK3_MODULES': 'xapp-gtk3-module', 'XDG_DATA_DIRS': '/usr/share/cinnamon:/usr/share/gnome:/home/oof/.local/share/flatpak/exports/share:/var/lib/flatpak/exports/share:/usr/local/share:/usr/share', 'PATH': '/home/oof/.nvm/versions/node/v18.17.0/bin:/home/oof/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin', 'GDMSESSION': 'cinnamon', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1000/bus', 'NVM_BIN': '/home/oof/.nvm/versions/node/v18.17.0/bin', 'GIO_LAUNCHED_DESKTOP_FILE_PID': '2335', 'GIO_LAUNCHED_DESKTOP_FILE': '/usr/share/applications/terminator.desktop', 'LC_NUMERIC': 'fi_FI.UTF-8', '_': '/usr/bin/python3', 'OLDPWD': '/home/oof/django/fileupload/minimal-django-file-upload-example/src', 'DJANGO_SETTINGS_MODULE': 'myproject.settings', 'TZ': 'UTC', 'RUN_MAIN': 'true', 'SERVER_NAME': 'localhost', 'GATEWAY_INTERFACE': 'CGI/1.1', 'SERVER_PORT': '8000', 'REMOTE_HOST': '', 'CONTENT_LENGTH': '2942692', 'SCRIPT_NAME': '', 'SERVER_PROTOCOL': 'HTTP/1.1', 'SERVER_SOFTWARE': 'WSGIServer/0.2', 'REQUEST_METHOD': 'POST', 'PATH_INFO': '/', 'QUERY_STRING': '', 'REMOTE_ADDR': '127.0.0.1', 'CONTENT_TYPE': 'multipart/form-data; boundary=----WebKitFormBoundaryzDqFUPB4gF0buimW', 'HTTP_HOST': '127.0.0.1:8000', 'HTTP_CONNECTION': 'keep-alive', 'HTTP_CACHE_CONTROL': 'max-age=0', 'HTTP_SEC_CH_UA': '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"', 'HTTP_SEC_CH_UA_MOBILE': '?0', 'HTTP_SEC_CH_UA_PLATFORM': '"Linux"', 'HTTP_UPGRADE_INSECURE_REQUESTS': '1', 'HTTP_ORIGIN': 'http://127.0.0.1:8000', 'HTTP_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', 'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7', 'HTTP_SEC_FETCH_SITE': 'same-origin', 'HTTP_SEC_FETCH_MODE': 'navigate', 'HTTP_SEC_FETCH_USER': '?1', 'HTTP_SEC_FETCH_DEST': 'document', 'HTTP_REFERER': 'http://127.0.0.1:8000/', 'HTTP_ACCEPT_ENCODING': 'gzip, deflate, br, zstd', 'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.9', 'HTTP_COOKIE': 'csrftoken=w8pIBqNHLRogHrP3uUWW0OWY4sulqEOa', 'wsgi.input': None, 'wsgi.errors': None, 'wsgi.version': (1, 0), 'wsgi.run_once': False, 'wsgi.url_scheme': 'http', 'wsgi.multithread': True, 'wsgi.multiprocess': False, 'wsgi.file_wrapper': None, 'CSRF_COOKIE': 'w8pIBqNHLRogHrP3uUWW0OWY4sulqEOa'}

	req.parse_file_upload(meta_shit, data) # Try to call it...
	exit(0)

```

seems to work as a fuzzing target. Now, let's craft some initial inputs for this target and see what we can cause.


Let's seed our corpus with this simple filething:

```
------a
Content-Disposition: form-data; name="csrfmiddlewaretoken"

mUlplnBwMIT12GoHr0Cxo0fntg4jAYaWISAXMDe3np77zX3ALKojeE1bnyouQsOW
------a
Content-Disposition: form-data; name="docfile"; filename="sample_file.txt"
Content-Type: text/plain

this is just some text whatever.
------a--
```


here is the final fuzzing harness:

```

import atheris

with atheris.instrument_imports():

	from django.http.request import *
	from django.conf import settings

from io import BytesIO # For making a bytearray to a file handle type thing
import sys
from mutator import *


# class HttpRequest:



meta_shit = {'SHELL': '/usr/bin/bash', 'SESSION_MANAGER': 'local/oof-h8-1440eo:@/tmp/.ICE-unix/1294,unix/oof-h8-1440eo:/tmp/.ICE-unix/1294', 'QT_ACCESSIBILITY': '1', 'COLORTERM': 'truecolor', 'XDG_CONFIG_DIRS': '/etc/xdg/xdg-cinnamon:/etc/xdg', 'XDG_SESSION_PATH': '/org/freedesktop/DisplayManager/Session0', 'NVM_INC': '/home/oof/.nvm/versions/node/v18.17.0/include/node', 'GNOME_DESKTOP_SESSION_ID': 'this-is-deprecated', 'LANGUAGE': 'en_US', 'TERMINATOR_DBUS_PATH': '/net/tenshu/Terminator2', 'LC_ADDRESS': 'fi_FI.UTF-8', 'LC_NAME': 'fi_FI.UTF-8', 'SSH_AUTH_SOCK': '/run/user/1000/keyring/ssh', 'CINNAMON_VERSION': '5.4.12', 'TERMINATOR_UUID': 'urn:uuid:dcf7087a-c448-4268-93e9-95099a2ac52f', 'DESKTOP_SESSION': 'cinnamon', 'LC_MONETARY': 'fi_FI.UTF-8', 'GTK_MODULES': 'gail:atk-bridge', 'XDG_SEAT': 'seat0', 'PWD': '/home/oof/django/fileupload/minimal-django-file-upload-example/src/for_django_3-0', 'LOGNAME': 'oof', 'XDG_SESSION_DESKTOP': 'cinnamon', 'QT_QPA_PLATFORMTHEME': 'qt5ct', 'XDG_SESSION_TYPE': 'x11', 'GPG_AGENT_INFO': '/run/user/1000/gnupg/S.gpg-agent:0:1', 'XAUTHORITY': '/home/oof/.Xauthority', 'XDG_GREETER_DATA_DIR': '/var/lib/lightdm-data/oof', 'GJS_DEBUG_TOPICS': 'JS ERROR;JS LOG', 'GDM_LANG': 'en_US', 'HOME': '/home/oof', 'LC_PAPER': 'fi_FI.UTF-8', 'LANG': 'en_US.UTF-8', 'LS_COLORS': 'rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:', 'XDG_CURRENT_DESKTOP': 'X-Cinnamon', 'VTE_VERSION': '6800', 'XDG_SEAT_PATH': '/org/freedesktop/DisplayManager/Seat0', 'TERMINATOR_DBUS_NAME': 'net.tenshu.Terminator21a9d5db22c73a993ff0b42f64b396873', 'GJS_DEBUG_OUTPUT': 'stderr', 'NVM_DIR': '/home/oof/.nvm', 'LESSCLOSE': '/usr/bin/lesspipe %s %s', 'XDG_SESSION_CLASS': 'user', 'TERM': 'xterm-256color', 'LC_IDENTIFICATION': 'fi_FI.UTF-8', 'GTK_OVERLAY_SCROLLING': '1', 'LESSOPEN': '| /usr/bin/lesspipe %s', 'USER': 'oof', 'DISPLAY': ':0', 'SHLVL': '1', 'NVM_CD_FLAGS': '', 'LC_TELEPHONE': 'fi_FI.UTF-8', 'LC_MEASUREMENT': 'fi_FI.UTF-8', 'XDG_VTNR': '7', 'XDG_SESSION_ID': 'c1', 'XDG_RUNTIME_DIR': '/run/user/1000', 'GTK3_MODULES': 'xapp-gtk3-module', 'XDG_DATA_DIRS': '/usr/share/cinnamon:/usr/share/gnome:/home/oof/.local/share/flatpak/exports/share:/var/lib/flatpak/exports/share:/usr/local/share:/usr/share', 'PATH': '/home/oof/.nvm/versions/node/v18.17.0/bin:/home/oof/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin', 'GDMSESSION': 'cinnamon', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1000/bus', 'NVM_BIN': '/home/oof/.nvm/versions/node/v18.17.0/bin', 'GIO_LAUNCHED_DESKTOP_FILE_PID': '2335', 'GIO_LAUNCHED_DESKTOP_FILE': '/usr/share/applications/terminator.desktop', 'LC_NUMERIC': 'fi_FI.UTF-8', '_': '/usr/bin/python3', 'OLDPWD': '/home/oof/django/fileupload/minimal-django-file-upload-example/src', 'DJANGO_SETTINGS_MODULE': 'myproject.settings', 'TZ': 'UTC', 'RUN_MAIN': 'true', 'SERVER_NAME': 'localhost', 'GATEWAY_INTERFACE': 'CGI/1.1', 'SERVER_PORT': '8000', 'REMOTE_HOST': '', 'CONTENT_LENGTH': '2942692', 'SCRIPT_NAME': '', 'SERVER_PROTOCOL': 'HTTP/1.1', 'SERVER_SOFTWARE': 'WSGIServer/0.2', 'REQUEST_METHOD': 'POST', 'PATH_INFO': '/', 'QUERY_STRING': '', 'REMOTE_ADDR': '127.0.0.1', 'CONTENT_TYPE': 'multipart/form-data; boundary=----a', 'HTTP_HOST': '127.0.0.1:8000', 'HTTP_CONNECTION': 'keep-alive', 'HTTP_CACHE_CONTROL': 'max-age=0', 'HTTP_SEC_CH_UA': '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"', 'HTTP_SEC_CH_UA_MOBILE': '?0', 'HTTP_SEC_CH_UA_PLATFORM': '"Linux"', 'HTTP_UPGRADE_INSECURE_REQUESTS': '1', 'HTTP_ORIGIN': 'http://127.0.0.1:8000', 'HTTP_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', 'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7', 'HTTP_SEC_FETCH_SITE': 'same-origin', 'HTTP_SEC_FETCH_MODE': 'navigate', 'HTTP_SEC_FETCH_USER': '?1', 'HTTP_SEC_FETCH_DEST': 'document', 'HTTP_REFERER': 'http://127.0.0.1:8000/', 'HTTP_ACCEPT_ENCODING': 'gzip, deflate, br, zstd', 'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.9', 'HTTP_COOKIE': 'csrftoken=w8pIBqNHLRogHrP3uUWW0OWY4sulqEOa', 'wsgi.input': None, 'wsgi.errors': None, 'wsgi.version': (1, 0), 'wsgi.run_once': False, 'wsgi.url_scheme': 'http', 'wsgi.multithread': True, 'wsgi.multiprocess': False, 'wsgi.file_wrapper': None, 'CSRF_COOKIE': 'w8pIBqNHLRogHrP3uUWW0OWY4sulqEOa'} # Taken from a running version. We have replaced the "boundary" with "------a"


@atheris.instrument_func
def TestOneInput(data):
	req = HttpRequest()
	req.parse_file_upload(meta_shit, BytesIO(data))



def CustomMutator(data, max_size, seed):

	try:
		#data = data.decode("ascii") # Try to decode ascii
		data = mutate(data)
	except:
		return # Ignore.


	data = atheris.Mutate(data, len(data))
	return data


settings.configure()
atheris.Setup(sys.argv, TestOneInput, custom_mutator=CustomMutator)
atheris.Fuzz()

#if __name__=="__main__":

#	settings.configure()




	#req = HttpRequest() # Create the object.
	#meta_shit = {} # Empty metadata for now.
	#data = b"" # Empty data for now.

	# Read data from input file.

	#fh = open(sys.argv[1], "rb")

	#data = fh.read()

	#fh.close()

	#data = BytesIO(data)







	# Actually let's use "----a" instead as separator. I think there was

	#print("settings.DATA_UPLOAD_MAX_MEMORY_SIZE. == "+str(settings.DATA_UPLOAD_MAX_MEMORY_SIZE))

#	res = req.parse_file_upload(meta_shit, data) # Try to call it...
#	print("res == "+str(res))
#	exit(0)



```

when I run the fuzzer with my custom mutator (the one for finding dos bugs), I get this crash:

```

oof.py: Running 1 inputs 1 time(s) each.
Running: crash-e942df18aa558cbb5a78070659e550fa052c0b29

 === Uncaught Python exception: ===
TooManyFilesSent: The number of files exceeded settings.DATA_UPLOAD_MAX_NUMBER_FILES.
Traceback (most recent call last):
  File "/home/oof/django/fileupload/shit/oof.py", line 22, in TestOneInput
    def TestOneInput(data):
  File "/home/oof/.local/lib/python3.10/site-packages/django/http/request.py", line 320, in parse_file_upload
    )
  File "/home/oof/.local/lib/python3.10/site-packages/django/http/multipartparser.py", line 128, in parse
    # Call the actual parse routine and close all open files in case of
  File "/home/oof/.local/lib/python3.10/site-packages/django/http/multipartparser.py", line 276, in _parse
    elif item_type == FILE:
TooManyFilesSent: The number of files exceeded settings.DATA_UPLOAD_MAX_NUMBER_FILES.

==13813== ERROR: libFuzzer: fuzz target exited
SUMMARY: libFuzzer: fuzz target exited


```

this may not seem interesting, but when you do a quick google search: https://www.djangoproject.com/weblog/2023/feb/14/security-releases/  you can find out, that this was actually a DOS vector!!!!!! This means that if we used an unpatched version of django, we could have found this same bug!!!!! This is fantastic! (here is the commit which fixed this: https://github.com/django/django/commit/628b33a854a9c68ec8a0c51f382f304a0044ec92)

Let's ignore some errors:

```
@atheris.instrument_func
def TestOneInput(data):
	req = HttpRequest()
	try:
		req.parse_file_upload(meta_shit, BytesIO(data))
	except (MultiPartParserError, TooManyFilesSent):
		# Just pass the exceptions
		return
```

and add a timeout on the command line: `python3 oof.py -max_len=10000000 -timeout=1 final_corp/` (this stops execution if it takes more than one second to process a specific input... (aka DOS!!!))!!

Whoops, found another bug:

```
#2905	NEW    cov: 341 ft: 1761 corp: 99/5344Kb lim: 10000000 exec/s: 121 rss: 82Mb L: 126550/2098963 MS: 4 CrossOver-Custom-ChangeBinInt-Custom-
#3081	REDUCE cov: 341 ft: 1761 corp: 99/5331Kb lim: 10000000 exec/s: 123 rss: 82Mb L: 112957/2098963 MS: 2 ChangeBinInt-Custom-
#3180	REDUCE cov: 341 ft: 1761 corp: 99/5330Kb lim: 10000000 exec/s: 122 rss: 82Mb L: 304/2098963 MS: 8 ChangeBit-Custom-EraseBytes-Custom-ChangeBinInt-Custom-ShuffleBytes-Custom-
#3303	REDUCE cov: 341 ft: 1761 corp: 99/5330Kb lim: 10000000 exec/s: 122 rss: 82Mb L: 2171/2098963 MS: 6 EraseBytes-Custom-ChangeBit-Custom-ChangeBit-Custom-
#3441	REDUCE cov: 341 ft: 1761 corp: 99/5329Kb lim: 10000000 exec/s: 122 rss: 82Mb L: 24641/2098963 MS: 6 CopyPart-Custom-ShuffleBytes-Custom-ChangeASCIIInt-Custom-
#3525	REDUCE cov: 341 ft: 1761 corp: 99/5328Kb lim: 10000000 exec/s: 121 rss: 82Mb L: 6826/2098963 MS: 8 EraseBytes-Custom-EraseBytes-Custom-EraseBytes-Custom-EraseBytes-Custom-
#3549	REDUCE cov: 341 ft: 1761 corp: 99/5326Kb lim: 10000000 exec/s: 122 rss: 82Mb L: 4815/2098963 MS: 8 CrossOver-Custom-ShuffleBytes-Custom-ChangeBit-Custom-ChangeBit-Custom-

 === Uncaught Python exception: ===
TooManyFieldsSent: The number of GET/POST parameters exceeded settings.DATA_UPLOAD_MAX_NUMBER_FIELDS.
Traceback (most recent call last):
  File "/home/oof/django/fileupload/shit/oof.py", line 23, in TestOneInput
    req = HttpRequest()
  File "/home/oof/.local/lib/python3.10/site-packages/django/http/request.py", line 320, in parse_file_upload
    )
  File "/home/oof/.local/lib/python3.10/site-packages/django/http/multipartparser.py", line 128, in parse
    # Call the actual parse routine and close all open files in case of
  File "/home/oof/.local/lib/python3.10/site-packages/django/http/multipartparser.py", line 218, in _parse
    and settings.DATA_UPLOAD_MAX_NUMBER_FIELDS is not None
TooManyFieldsSent: The number of GET/POST parameters exceeded settings.DATA_UPLOAD_MAX_NUMBER_FIELDS.

==13928== ERROR: libFuzzer: fuzz target exited
SUMMARY: libFuzzer: fuzz target exited
MS: 8 ShuffleBytes-Custom-ChangeBinInt-Custom-ChangeByte-Custom-CMP-Custom- DE: "\377\377\377\377\377\377\377\377"-; base unit: 87c89a56f1436dbbcc24526a08281eeb57f035c3
artifact_prefix='./'; Test unit written to ./crash-210c4e86ddf264e239b905370c0e238a54e9d874

```

Let's ignore that exception too (for now...)

Fuck! Another uncaught exception:

```

#25037	REDUCE cov: 343 ft: 1790 corp: 115/5447Kb lim: 10000000 exec/s: 108 rss: 82Mb L: 9058/2098963 MS: 6 PersAutoDict-Custom-CopyPart-Custom-ChangeASCIIInt-Custom- DE: "\001\000"-

 === Uncaught Python exception: ===
OSError: [Errno 36] File name too long: '/tmp/tmps4a0b9mx.upload. fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fddlewaretoken'
Traceback (most recent call last):
  File "/home/oof/django/fileupload/shit/oof.py", line 23, in TestOneInput
    req = HttpRequest()
  File "/home/oof/.local/lib/python3.10/site-packages/django/http/request.py", line 320, in parse_file_upload
    )
  File "/home/oof/.local/lib/python3.10/site-packages/django/http/multipartparser.py", line 128, in parse
    # Call the actual parse routine and close all open files in case of
  File "/home/oof/.local/lib/python3.10/site-packages/django/http/multipartparser.py", line 304, in _parse
    content_length = None
  File "/home/oof/.local/lib/python3.10/site-packages/django/core/files/uploadhandler.py", line 167, in new_file
    """
  File "/home/oof/.local/lib/python3.10/site-packages/django/core/files/uploadedfile.py", line 76, in __init__
    _, ext = os.path.splitext(name)
  File "/usr/lib/python3.10/tempfile.py", line 679, in NamedTemporaryFile
  File "/usr/lib/python3.10/tempfile.py", line 693, in opener
    def opener(*args):
  File "/usr/lib/python3.10/tempfile.py", line 392, in _mkstemp_inner
    file = _os.path.join(dir, pre + name + suf)
OSError: [Errno 36] File name too long: '/tmp/tmps4a0b9mx.upload. fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fil; fddlewaretoken'

==13954== ERROR: libFuzzer: fuzz target exited
SUMMARY: libFuzzer: fuzz target exited
MS: 4 CopyPart-Custom-CopyPart-Custom-; base unit: 4024ceda25179eca61fe5ea9cd7ffd141b7b5085
artifact_prefix='./'; Test unit written to ./crash-a9f7cbf6b5c2d029d3d0410513815f12b8f12af4


```

the interesting thing is that the uploadhandler should make sure that such a scenario never happens???? That is quite odd.. or maybe not:

```
class TemporaryUploadedFile(UploadedFile):
    """
    A file uploaded to a temporary location (i.e. stream-to-disk).
    """

    def __init__(self, name, content_type, size, charset, content_type_extra=None):
        _, ext = os.path.splitext(name) # <----- CRASH HERE
        file = tempfile.NamedTemporaryFile(
            suffix=".upload" + ext, dir=settings.FILE_UPLOAD_TEMP_DIR
        )
        super().__init__(file, name, content_type, size, charset, content_type_extra)

    def temporary_file_path(self):
        """Return the full path of this file."""
        return self.file.name

    def close(self):
        try:
            return self.file.close()
        except FileNotFoundError:
            # The file was moved or deleted before the tempfile could unlink
            # it. Still sets self.file.close_called and calls
            # self.file.file.close() before the exception.
            pass
```



Let's see what we find...

## Fuzzing results...

Uh oh. I think I actually found a bug... as of writing this on July 12th 2024, this vulnerability hasn't yet been publically disclosed, this blog post will be updated when this security issue is publically disclosed...

Thank you for your patience!


In the meantime, let's try our fuzzer on some other stuff. Let's try fuzzing the ruby library called `rack` maybe? There may be some bugs hiding in that code. Now, I think a good tool for fuzzing ruby code is ruzzy (https://blog.trailofbits.com/2024/03/29/introducing-ruzzy-a-coverage-guided-ruby-fuzzer/) , but it doesn't support python custom mutators because reasons. This sucks. I think I need to mod ruzzy, such that I can use python mutators with it.

## Adding python custom mutator support for libfuzzer

Ok, so I think here is some stuff which may help us: https://github.com/MozillaSecurity/libfuzzer-python-bridge (possibly). It is some minimal code, which adds support for python custom mutators in libfuzzer. Let's add some of the python fuzzer bridge code to the ruzzy fuzzer.

I actually modified the python bridge with this diff:

```
diff --git a/python_bridge.cpp b/python_bridge.cpp
index 1c3cb84..e44176b 100644
--- a/python_bridge.cpp
+++ b/python_bridge.cpp
@@ -134,9 +134,8 @@ static void LLVMFuzzerInitPythonModule() {
       py_fatal_error();
     }
   } else {
-    fprintf(stderr, "Warning: No Python module specified, please set the "
-                    "LIBFUZZER_PYTHON_MODULE environment variable.\n");
-    py_fatal_error();
+    fprintf(stderr, "Warning: No Python module specified, using the default libfuzzer mutator (for now).\n");
+    // py_fatal_error();
   }


@@ -154,6 +153,10 @@ static void LLVMFuzzerFinalizePythonModule() {

 extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                           size_t MaxSize, unsigned int Seed) {
+  // First check if the custom python mutator is specified:
+  if (!py_module) { // No custom python mutator, so therefore just mutate regularly. (LLVMFuzzerMutate is the default mutator.)
+    return LLVMFuzzerMutate(Data, size, MaxSize);
+  }
   PyObject* py_args = PyTuple_New(4);

   // Convert Data and Size to a ByteArray
@@ -206,7 +209,14 @@ extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
     }
     memcpy(Data, PyByteArray_AsString(py_value), ReturnedSize);
     Py_DECREF(py_value);
-    return ReturnedSize;
+    // return ReturnedSize; // Instead of returning the python custom mutator, we should also try to use the original custom mutator too (maybe).
+    if (getenv("FUZZ_ONLY_CUSTOM")) { // Only fuzz with the custom mutator
+      return ReturnedSize;
+    }
+
+
+    return LLVMFuzzerMutate(Data, ReturnedSize, MaxSize);
+
   } else {
     if (PyErr_Occurred())
       PyErr_Print();

```

now, we need to add this code to the ruzzy ruby fuzzer.





































