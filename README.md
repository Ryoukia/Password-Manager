# PASSWORD MANAGER
## Neat but insecure password manager created by Colin Lessor. Converts passwords into SHA256 hashes and stores them in a pickle for portability

<h3>I have always mistrusted password managers, even knowing that most security experts recommend that you use one, so I built one for myself to better understand the principles behind them. I am happy to report that I learned what makes them so advisable and would use one myself.</h3>
<h3>I will state here again that this password manager is most likely not secure, and could be breached, so I don't recommend downloading this and using it.</h3>
<h3>If you still want to try it out though, you have to initialize a passwordmanager object with parameter password, which is a string which will serve as the access code to the entire password manager.  Use the set function with parameters str domain and str password to add a website and its corresponding password to the manager. If password is left blank, a secure password will be pseudorandomly generated for you.
  Call the get function with parameter str domain, which is the url of a website, to return the password corresponding to that website.
Call the remove funciton with parameter str domain, which is the url of a website, to remove the domain:password pair from the manager.</h3>

<h3></h3>
