# Finance web app

The Finance web app was written for Harvard's CS50 introduction course, problem set 8 (pset8).

In the app, you can register yourself, log in, and then 'buy' and 'sell' stocks. You are not actually buying or selling anything, but simply getting your 'purchases' registered in the SQLite database.

# Starting the server

The server is started in development mode by running `flask run` in the root of the project.

Upon starting the server, an SQLite3 database file called `finance.db` is automatically created by the SQLAlchemy module.

## API environment variables

The app fetches live stock information from [iexcloud.io](https://iexcloud.io/console). In order to run the app, you need to get a Publishable API token from there and set that token as an environment variable in your computer, like this:

```
export API_KEY=your_token
```

## Licence

MIT
