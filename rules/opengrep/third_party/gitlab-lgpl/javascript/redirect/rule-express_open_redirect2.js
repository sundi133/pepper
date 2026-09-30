// License: GNU Lesser General Public License v3.0
// Rule ref: rules_lgpl_javascript_redirect_rule-express-open-redirect2

const path = require('path')

module.exports = function (app) {
  // http://localhost:3000/redirect-two/
  app.get('/redirect-two', (req, res) => {
    const filePath = path.join(__dirname, 'public', 'open_redirect2.html')
    res.sendFile(filePath)
  })

  app.get('/redirect-two/1', function (req, res) {
    const { url } = req.query
    // Testing header() method
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.header('Location', url)
    res.status(302).send()
  })

  app.get('/redirect-two/2', function (req, res) {
    const { url } = req.query
    // Testing writeHead() method
    res.writeHead(302, 'Redirect', {
      'Content-Type': 'text/html',
      // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
      location: url,
      custom: 'hi'
    })
    res.send()
  })

  app.get('/redirect-two/3', (req, res) => {
    const { url } = req.query
    // Testing set() method
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.status(302).set('Location', url).end()
  })

  app.get('/redirect-two/4', (req, res) => {
    const { url } = req.query
    // Testing location() method
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.location(url).status(302).end()
  })

  app.get('/redirect-two/5', (req, res) => {
    const { url } = req.query
    // Testing append() method
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.append('Location', url)
    res.status(302).send()
  })

  app.get('/redirect-two/6', (req, res) => {
    const { url } = req.query
    // Testing setHeader() method
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.setHeader('Location', url)
    res.statusCode = 302
    res.end()
  })

  app.get('/redirect-two/7', function (req, res) {
    // Testing header() method - inline request parameter
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.header('Location', req.query.url)
    res.status(302).send()
  })

  app.get('/redirect-two/8', function (req, res) {
    // Testing writeHead() method - inline request parameter
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.writeHead(302, { location: req.query.url })
    res.send()
  })

  app.get('/redirect-two/9', (req, res) => {
    // Testing set() method - inline request parameter
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.status(302).set('Location', req.query.url).end()
  })

  app.get('/redirect-two/10', (req, res) => {
    // Testing location() method - inline request parameter
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.location(req.query.url).status(302).end()
  })

  app.get('/redirect-two/11', (req, res) => {
    // Testing append() method - inline request parameter
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.append('Location', req.query.url)
    res.status(302).send()
  })

  app.get('/redirect-two/12', (req, res) => {
    // Testing setHeader() method - inline request parameter
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.setHeader('Location', req.query.url)
    res.statusCode = 302
    res.end()
  })

  //********** */

  app.get('/redirect-two/13', function (req, res) {
    const { url } = req.query
    // User input appended to hardcoded url domain in an unsafe manner
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.header('Location', 'http://localhost' + url)
    res.status(302).send()
  })

  app.get('/redirect-two/14', (req, res) => {
    // Hardcoded url, will redirect to this page itself - True Negative
    // ok: rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.header('Location', '/redirect-two')
    res.status(302).send()
  })

  app.get('/redirect-two/15', (req, res) => {
    const { url } = req.query
    // Safely Hardcoded domain - True Negative
    // ok: rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.header('Location', 'http://localhost:3000/' + url)
    res.status(302).send()
  })

  app.get('/redirect-two/16', function (req, res) {
    // User input prepended to hardcoded url path in an unsafe manner
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.header('Location', req.query.url + '/redirect-two')
    res.status(302).send()
  })

  app.get('/redirect-two/17', function (req, res) {
    // Testing deprecated way of fetching request parameter
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.status(302).set('Location', req.param('url')).end()
  })

  app.get('/redirect-two/18', function (req, res) {
    // Testing slightly different syntax - with join method
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res
      .status(302)
      .set('Location', [req.query.url, '?random=', req.query.qp].join(''))
      .end()
  })

  app.get('/redirect-two/19/:url', (req, res) => {
    // Testing different function syntax and url in path
    const url = req.params.url
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.status(302).set('Location', url).end()
  })

  app.get('/redirect-two/20', function namedFUN (req, res) {
    // Testing named function
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.status(302).set('Location', req.query.url).end()
  })

  const allowedUrls = [
    'http://localhost:3000/redirect',
    'http://localhost:3000/'
  ]

  app.get('/redirect-two/21', (req, res) => {
    const url = decodeURIComponent(req.query.url)

    if (allowedUrls.includes(url)) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
      res.status(302).set('Location', url).end()
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect-two/22', (req, res) => {
    const url = decodeURIComponent(req.query.url)
    const isAllowed = allowedUrls.includes(url)

    if (isAllowed) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
      res.status(302).set('Location', url).end()
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect-two/23', (req, res) => {
    const url = decodeURIComponent(req.query.url)
    const isAllowed = allowedUrls.indexOf(url) !== -1

    if (isAllowed) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
      res.status(302).set('Location', url).end()
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect-two/24', (req, res) => {
    const url = decodeURIComponent(req.query.url)

    if (allowedUrls.indexOf(url) !== -1) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
      res.status(302).set('Location', url).end()
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect-two/25', (req, res) => {
    const url = decodeURIComponent(req.query.url)
    const isAllowed = allowedUrls.find(element => element === url) !== undefined

    if (isAllowed) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
      res.status(302).set('Location', url).end()
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect-two/26', (req, res) => {
    const url = decodeURIComponent(req.query.url)

    if (allowedUrls.find(element => element === url) !== undefined) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
      res.status(302).set('Location', url).end()
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  const allowedUrlsSet = new Set([
    'http://localhost:3000/redirect',
    'http://localhost:3000/'
  ])

  app.get('/redirect-two/27', (req, res) => {
    const url = decodeURIComponent(req.query.url)
    const isAllowed = allowedUrlsSet.has(url)

    if (isAllowed) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
      res.status(302).set('Location', url).end()
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect-two/28', function (req, res) {
    // Testing case insensitivity of location
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.status(302).set('location', req.query.url).end()
  })

  // *******

  app.get('/redirect-two/29', function (req, res) {
    const url = 'http://localhost:3000/redirect-two'
    // Hardcoded value in header() method, not inline - True Negative
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.header('Location', url)
    res.status(302).send()
  })

  app.get('/redirect-two/30', function (req, res) {
    const { url } = req.query
    // Hardcoded value in writeHead() method for location header - True Negative
    res.writeHead(302, 'Redirect', {
      'Content-Type': 'text/html',
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
      location: 'http://localhost:3000/redirect-two',
      custom: url
    })
    res.send()
  })

  app.get('/redirect-two/31', (req, res) => {
    const { url } = 'http://localhost:3000/redirect-two'
    // Hardcoded value in set() method for location header, not inline - True Negative
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.status(302).set('Location', url).end()
  })

  app.get('/redirect-two/32', (req, res) => {
    const { url } = 'http://localhost:3000/redirect-two'
    // Hardcoded value in location() method for location header, not inline - True Negative
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.location(url).status(302).end()
  })

  app.get('/redirect-two/33', (req, res) => {
    // Hardcoded value in location() method for location header - True negative
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.location('http://localhost:3000/redirect-two').status(302).end()
  })

  app.get('/redirect-two/34', (req, res) => {
    const { url } = 'http://localhost:3000/redirect-two'
    // Hardcoded value in append() method for location header - True negative
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.append('Location', url)
    res.status(302).send()
  })

  app.get('/redirect-two/35', (req, res) => {
    const url = 'http://localhost:3000/redirect-two'
    // Hardcoded value in setHeader() method for location header, not inline - True negative
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.setHeader('Location', url)
    res.statusCode = 302
    res.end()
  })

  app.get('/redirect-two/36', (req, res) => {
    // Safely Hardcoded domain plus user input in header() method, inline - True Negative
    // ok: rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.header('Location', 'http://localhost:3000/' + req.query.url)
    res.status(302).send()
  })

  app.get('/redirect-two/37', (req, res) => {
    const url = 'http://localhost:3000/' + req.query.url
    // Safely Hardcoded domain plus user input in header() method, not inline - True Negative
    // ok: rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.header('Location', url)
    res.status(302).send()
  })

  app.get('/redirect-two/38', function (req, res) {
    // Safely Hardcoded domain plus user input in writeHead() method, inline - True Negative
    res.writeHead(302, 'Redirect', {
      'Content-Type': 'text/html',
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
      location: 'http://localhost:3000/' + req.query.url,
      custom: 'hi'
    })
    res.send()
  })

  app.get('/redirect-two/39', function (req, res) {
    const url = 'http://localhost:3000/' + req.query.url
    // Safely Hardcoded domain plus user input in writeHead() method, not inline - True Negative
    res.writeHead(302, 'Redirect', {
      'Content-Type': 'text/html',
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
      location: url,
      custom: 'hi'
    })
    res.send()
  })

  app.get('/redirect-two/40', (req, res) => {
    const url = 'http://localhost:3000/' + req.query.url
    // Safely Hardcoded domain plus user input in set() method, not inline - True Negative
    // ok: rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.status(302).set('Location', url).end()
    res.status(302).send()
  })

  app.get('/redirect-two/41', (req, res) => {
    // Safely Hardcoded domain plus user input in writeHead() method, inline - True Negative
    // ok: rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res
      .status(302)
      .set('Location', 'http://localhost:3000/' + req.query.url)
      .end()
    res.status(302).send()
  })

  app.get('/redirect-two/42', (req, res) => {
    const url = 'http://localhost:3000/' + req.query.url
    // Safely Hardcoded domain plus user input in location() method, not inline - True Negative
    // ok: rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.location(url).status(302).end()
  })

  app.get('/redirect-two/43', (req, res) => {
    // Safely Hardcoded domain plus user input in location() method, inline - True Negative
    // ok: rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res
      .location('http://localhost:3000/' + req.query.url)
      .status(302)
      .end()
  })

  app.get('/redirect-two/44', (req, res) => {
    const url = 'http://localhost:3000/' + req.query.url
    // Safely Hardcoded domain plus user input in append() method, not inline - True Negative
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.append('Location', url)
    res.status(302).send()
  })

  app.get('/redirect-two/45', (req, res) => {
    // Safely Hardcoded domain plus user input in append() method, inline - True Negative
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.append('Location', 'http://localhost:3000/' + req.query.url)
    res.status(302).send()
  })

  app.get('/redirect-two/46', (req, res) => {
    const url = 'http://localhost:3000/' + req.query.url
    // Safely Hardcoded domain plus user input in setHeader() method, not inline - True Negative
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.setHeader('Location', url)
    res.statusCode = 302
    res.end()
  })

  app.get('/redirect-two/47', (req, res) => {
    // Safely Hardcoded domain plus user input in setHeader() method, inline - True Negative
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect2
    res.setHeader('Location', 'http://localhost:3000/' + req.query.url)
    res.statusCode = 302
    res.end()
  })
}
