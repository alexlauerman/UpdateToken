# UpdateToken
This Burp extension is used to updated token values tie to a session, such as a bearer token. Specifically, it pulls a authorization token out of a JSON response and includes it in the headers.

By slightly modifying the code, you can also use this to update CSRF tokens without using macros, which are very inefficent becaues the require a request after reach request.

If you are signing into multiple sessions at the same time, I would disable this, as it wil likely cause issues.
