// License: GNU Lesser General Public License v3.0
const path = require('path')

module.exports = function (app) {
  // http://localhost:3000/redirect
  app.get('/redirect', (req, res) => {
    const filePath = path.join(__dirname, 'public', 'open_redirect.html')
    res.sendFile(filePath)
  })

  app.get('/redirect/1', (req, res) => {
    const { url } = req.query
    if (url) {
      // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect
      return res.redirect(url)
    }
    return res.send('URL parameter is missing')
  })

  app.get('/redirect/2', (req, res) => {
    // hardcoded url - true negative
    // ok: rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect('/redirect')
  })

  app.post('/redirect/3', function (req, res) {
    // Redirect through post body - form submission
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect(req.body.url)
  })

  app.get('/redirect/4', function (req, res) {
    // User input appended to hardcoded url domain in an unsafe manner
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect('http://sdcssf' + req.query.url)
  })
  app.get('/redirect/5', function (req, res) {
    // User input prepended to hardcoded url path in an unsafe manner
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect(req.query.url + '/asdad')
  })

  app.get('/redirect/6', function (req, res) {
    // deprecated way, also passing status code
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect(302, req.param('url'))
  })

  app.get('/redirect/7', function (myrequest, res) {
    // deprecated method - not inline
    // also testing different request parameter name
    var target = myrequest.param('url')
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect(target)
  })

  app.get('/redirect/8', function (req, res) {
    // testing slightly complicated syntax - with conditional operator
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect(
      req.param('url') && req.param('url') != ''
        ? req.param('url')
        : '/redirect'
    )
  })

  app.get('/redirect/9', function (req, res) {
    // Testing slightly different syntax - with join method
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect([req.query.url, '?section=', req.query.qp].join(''))
  })

  app.get('/redirect/10/:url', (req, res) => {
    // Testing different function syntax and url in path
    const url = req.params.url
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect(url)
  })

  app.get('/redirect/11', function namedFUN (req, res) {
    // Testing named function
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect([req.query.url, '?section=', req.query.qp].join(''))
  })

  app.get('/redirect/12', function namedFUN (req, res) {
    var localVar = '/redirect'
    // Safe - true negative
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect(localVar)
  })

  const allowedUrls = [
    'http://localhost:3000/redirect',
    'http://localhost:3000/'
  ]

  app.get('/redirect/13', (req, res) => {
    const url = decodeURIComponent(req.query.url)

    if (allowedUrls.includes(url)) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect
      res.redirect(url)
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect/14', (req, res) => {
    const url = decodeURIComponent(req.query.url)
    const isAllowed = allowedUrls.includes(url)

    if (isAllowed) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect
      res.redirect(url)
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect/15', (req, res) => {
    const url = decodeURIComponent(req.query.url)
    const isAllowed = allowedUrls.indexOf(url) !== -1

    if (isAllowed) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect
      res.redirect(url)
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect/16', (req, res) => {
    const url = decodeURIComponent(req.query.url)

    if (allowedUrls.indexOf(url) !== -1) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect
      res.redirect(url)
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect/17', (req, res) => {
    const url = decodeURIComponent(req.query.url)
    const isAllowed = allowedUrls.find(element => element === url) !== undefined

    if (isAllowed) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect
      res.redirect(url)
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect/18', (req, res) => {
    const url = decodeURIComponent(req.query.url)

    if (allowedUrls.find(element => element === url) !== undefined) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect
      res.redirect(url)
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  const allowedUrlsSet = new Set([
    'http://localhost:3000/redirect',
    'http://localhost:3000/'
  ])

  app.get('/redirect/19', (req, res) => {
    const url = decodeURIComponent(req.query.url)
    const isAllowed = allowedUrlsSet.has(url)

    if (isAllowed) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect
      res.redirect(url)
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect/20', (req, res) => {
    const url = decodeURIComponent(req.query.url)

    if (allowedUrlsSet.has(url)) {
      // Validation check
      // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect
      res.redirect(url)
    } else {
      res.status(400).send('Invalid redirect URL')
    }
  })

  app.get('/redirect/21', (req, res) => {
    const url = decodeURIComponent(req.query.url)

    // Safe - domain hardcoded
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect('http://localhost/' + url)
  })

  app.get('/redirect/22', (req, res) => {
    const url = decodeURIComponent(req.query.url)

    // Vulnerable as attacker can send @www.google.com for successful redirection
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect('http://localhost' + url)
  })

  app.get('/redirect/23', (req, res) => {
    // Safe - domain hardcoded
    // ok:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect('http://localhost/' + req.query.url)
  })

  app.get('/redirect/24', (req, res) => {
    // Vulnerable as attacker can send @www.google.com for successful redirection
    // ruleid:rules_lgpl_javascript_redirect_rule-express-open-redirect
    res.redirect('http://localhost' + req.query.url)
  })
}
