## Description
This module provide a mechanism to sync messages between workers for your module.


## Directives

Syntax: **sync_msg_timeout** `time`

Default: `1s`

Context: `main`

This directive set the interval of workers readding the commands from share memory.


Syntax: **sync_msg_shm_zone_size** `size`

Default: `2MB`

Context: `main`

This directive set the size of share memory which used to store the commands.


## API
```c
#define ngx_sync_msg_send(t, c, m)                                             \
    ngx_sync_msg_send_module_index(t, c, m.index)
#define ngx_sync_msg_send_locked(t, c, m)                                      \
    ngx_sync_msg_send_locked_module_index(t, c, m.index)

#define ngx_sync_special_msg_send(t, c, m)                                     \
    ngx_sync_msg_special_send_module_index(t, c, m.index)
#define ngx_sync_special_msg_send_locked(t, c, m)                              \
    ngx_sync_msg_special_send_locked_module_index(t, c, m.index)


void ngx_sync_msg_lock();
void ngx_sync_msg_unlock();

ngx_int_t ngx_sync_msg_send_module_index(ngx_str_t *title, ngx_buf_t *content,
    ngx_uint_t index);
ngx_int_t ngx_sync_msg_send_locked_module_index(ngx_str_t *title,
    ngx_buf_t *content, ngx_uint_t index);
ngx_int_t ngx_sync_msg_special_send_module_index(ngx_str_t *title,
    ngx_buf_t *content, ngx_uint_t index);
ngx_int_t ngx_sync_msg_special_send_locked_module_index(ngx_str_t *title,
    ngx_buf_t *content, ngx_uint_t index);


extern ngx_flag_t ngx_sync_msg_enable;
extern ngx_sync_msg_read_filter_pt ngx_sync_msg_top_read_filter;
extern ngx_sync_msg_crashed_filter_pt ngx_sync_msg_top_crashed_filter;

```


## Usage

You can get some information from the demo [https://github.com/yzprofile/ngx_sync_msg_module/tree/master/demo](https://github.com/yzprofile/ngx_sync_msg_module/tree/master/demo)


## Copyright & License

These codes are licenced under the BSD license.

Copyright (C) 2012-2013 by Zhuo Yuan (yzprofile) <yzprofiles@gmail.com>, Alibaba Inc.

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
