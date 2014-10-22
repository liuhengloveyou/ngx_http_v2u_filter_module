ngx_http_v2u_filter_module
==========================

把HTTP响应体显示成unicode编码序列

例如: 我爱你 = \u6211\u7231\u4f60

配置示例
--------

    location /demo {
        content_by_lua 'ngx.say("hello, world. 我爱你, 地球.")';
        v2u_body on;
    }
