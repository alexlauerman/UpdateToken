# UpdateToken
This Burp extension is used to updated bearer tokens, similar to how Burp's cooke jar works. Specifically, it pulls a authorization token out of a JSON response and includes it in future request headers.

It will likely need some customization, so it's more of an extension template for you to modify, than something you can use without any changes. I've used this to update a CSRF token, and I've left that code commented out, so you can use this to update CSRF tokens as needed (e.g. ones that quickly time out), without using macros. Macros are very inefficent because they require a second request after reach request.

If you are signing into multiple sessions at the same time, I would disable this extension, as it wil likely cause issues for you.

See the [Releases](https://github.com/alexlauerman/UpdateToken/releases) tab for a pre-built jar.
