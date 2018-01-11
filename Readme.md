# ocp-libsodium-js

[Js\_of\_ocaml](https://ocsigen.org/js_of_ocaml) ready version of
[libsodium.js](https://github.com/jedisct1/libsodium.js).

## Usage

When compiling an OCaml program which uses this library to Javascript, you need
to load the resulting Javascript asynchronously.

This can be done by prefixing and postfixing with the provided
[`pre.js`](static/pre.js) and [`post.js`](static/post.js).

```bash
cat static/pre.js pathto/myapp.js static/post.js > app.js
```


```html
<html>
  <head>
    <script src="app.js"></script>
    <script src="sodium.js" async></script>
  </head>
</html>
```
