# Trading API

## About This Project 

This project is the backend API for my mock trading full stack project for which the link link can be found <a href="https://elaborate-maamoul-c9d4b1.netlify.app/" target="blank">here</a> and the front end code-base <a href="https://github.com/mulcharv/tradingfrontend" target="blank">here</a>.

This project has the following routes and features:

* Passport JS strategies to sign up as a user and authenticate a JWT.
* POST username, password, and password confirmation to sign up.
* Use of BcryptJs to salt and hash submitted passwords for secure storage on database.
* Automated creation of fund account, stock portfolio, watchlist, and transaction activity schema instances linked to user upon sign up.
* POST username and password to login, with creation JWT upon successful login, set in local storage and used to authenticate all routes.
* GET latest data (last stock price) of stock by stock symbol.
* GET general information (exchange, country, company name) of stock by stock symbol.
* GET stock prices through an interval of time (day, week, month, 3 months, etc.) via the stock symbol and chosen interval.
* PUT user fund account with deposits and withdrawals, also logs these transactions into the activity schema.
* PUT a stock purchase or sell in a user's portfolio, which takes the price and quantity and either adds it to the stock's position (purchase) or calculates the realized gain/loss (sell), with both being logged into the user activity. Safeguards are in place to not sell more stocks then owned, and not buy at a price which exceeds the fund account balance.
* GET user fund account by user ID.
* GET user's position on a stock through user ID.
* GET user portfolio through user ID.
* GET a watchlist of stocks for the user through user ID.
* PUT a stock in/out from a watchlist through the user ID and stock symbol.
* GET user activity through user ID.
* Have all GET requests for stock information (latest data, interval, general information) connect fetch requests to the <a href="https://marketstack.com/" target="blank">Marketstack API</a> and parse JSON data in response for use in project API routes.

This project uses the Node.js web framework Express to build out the API and its routes. It also uses Mongoose to build out data models for comment, post, and user schemas.

## Key Learnings 

This project followed my Blog API project, which allowed me to expand on what I learned of Express APIs in that project. It was also my first time fetching data in a backend API. Through these experiences I learned the following: 

* Nesting Mongoose schemas for logical data flow and retrieval. For this project that meant creating a position schema (for purchase/sell orders of a stock) and setting that as the item template for an array of positions within the portfolio schema. Having both the portfolio and the position schemas have the user schema as the base reference allows them to both
be found with the user ID in GET requests.
* Creating and updating data schemas as secondary actions to other ones being primarily affected by a user decision (ie. updating the activity schema instance when funds are added/withdrawn or stocks purchased/sold).
* Integrating error handling for fetch requests to another API within this project's routes (ie. responding with a 404 error when a stock symbol is entered that is not found in the Marketstack API databse).
* Finding the calendar date for a set interval (ie. 1 week) back from the current date. This proved to be challenging as it required converting the current date to milliseconds since epoch (January 1 1970 UTC), subtracting the amount of milliseconds from it that make up the set interval, and then converting that to a calendar date formatted in a way that met the query requirements for the Marketstack API request.

## Future Opportunities 

This project was wide in its scope and features, which presented a couple of things I would like to add in the future: 

* A data schema that keeps a log of portfolio performance (realized gain/loss) across dates it changed for possible presentation as a graph on the front end.
* Using an API with currency conversions to allow all schema instances to store amounts in the user's chosen currency instead of default to USD.
* Create routes to change the user's password for added security given it deals with high value assets.

## Acknowledgements 

Resources that were helpful in creating this application.

* <a href="https://www.npmjs.com/package/multer" target="blank">Multer</a>
* <a href="https://www.npmjs.com/package/jwt-decode" target="blank">JWT Decode</a>
* <a href="https://www.npmjs.com/package/dotenv" target="blank">Dotenv</a>
* <a href="https://www.npmjs.com/package/luxon" target="blank">Luxon</a>
* <a href="https://www.passportjs.org/" target="blank">PassportJs</a>
* <a href="https://www.npmjs.com/package/bcryptjs" target="blank">BcyrptJs</a>
* <a href="https://www.npmjs.com/package/node-fetch" target="blank">Node Fetch</a>

## About Me 

Visit my <a href="https://github.com/mulcharv" target="blank">about me</a> page to learn what I'm up to and contact me. 

