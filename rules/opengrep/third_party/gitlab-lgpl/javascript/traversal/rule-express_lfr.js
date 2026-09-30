// License: GNU Lesser General Public License v3.0
// source (original): https://github.com/ajinabraham/njsscan/blob/master/tests/assets/node_source/true_positives/semantic_grep/traversal/express_hbs_lfr.js
// hash: e7a0a61
const cookieParser = require('cookie-parser');
module.exports = function (app) {
    app.use(cookieParser());

    // http://localhost:3000/traversal/express-lfr/1?template=index 
    app.get("/traversal/express-lfr/1", async (req, res) => {
        const template = req.query.template
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(template, { title: "Title" })
    });

    // http://localhost:3000/traversal/express-lfr/2?template=user 
    app.get("/traversal/express-lfr/2", async (req, res) => {
        const template = req.query.template.concat('/user')
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(template, { title: "User Page" })
    });

    // http://localhost:3000/traversal/express-lfr/3?template=user 
    app.get("/traversal/express-lfr/3", async (req, res) => {
        const template = req.query.template + '/user'
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(template, { title: "User Page" })
    });

    // http://localhost:3000/traversal/express-lfr/4?template=user
    app.get("/traversal/express-lfr/4", async (req, res) => {
        var indexPath = req.query.template;
        indexPath = indexPath + "/user"
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(indexPath, { title: "User Page" })
    });

    // http://localhost:3000/traversal/express-lfr/5?template=user
    app.get("/traversal/express-lfr/5", async (req, res) => {
        var indexPath = req.query.template;
        indexPath = indexPath.concat("/user");
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(indexPath, { title: "User Page" })
    });

    // http://localhost:3000/traversal/express-lfr/6?template=../views2/user
    app.get("/traversal/express-lfr/6", async (req, res) => {
        const path = require('path')
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(req.query.template, { title: "User Page" })
    });

    // http://localhost:3000/traversal/express-lfr/safe/1
    app.get("/traversal/express-lfr/safe/1", async (req, res) => {
        // ok: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render("user/user", { title: "User Page" })
    });

    // http://localhost:3000/traversal/express-lfr/safe/2
    app.get("/traversal/express-lfr/safe/2", async (req, res) => {
        var indexPath = "index";
        // ok: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(indexPath, { title: "Index Page" })
    });

    // http://localhost:3000/traversal/express-lfr/safe/3
    app.get("/traversal/express-lfr/safe/3", async (req, res) => {
        var indexPath = "user/";
        indexPath += "user"
        // ok: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(indexPath, { title: "User Page" })
    });

    // http://localhost:3000/traversal/express-lfr/7
    /* 
        curl --location 'http://localhost:3000/traversal/express-lfr/7' \
        --header 'Cookie: user=index; sId=555'
    */
    app.get("/traversal/express-lfr/7", async (req, res) => {
        console.log("cookies", req.cookies)
        const template = req.cookies.user
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(template, { title: "Title" })
    });

    app.set('trust proxy', 1);

    // http://localhost:3000/traversal/express-lfr/8/inxex
    /*
        curl --location 'http://localhost:3000/traversal/express-lfr/8' \
        --header 'X-Forwarded-For: index'
     */
    app.get("/traversal/express-lfr/8", async (req, res) => {
        const template = req.ip
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(template, { title: "Title" })
    });

    // http://localhost:3000/traversal/express-lfr/9/inxex
    /*
        curl --location 'http://localhost:3000/traversal/express-lfr/9' \
        --header 'X-Forwarded-For: index'
     */
    app.get("/traversal/express-lfr/9", async (req, res) => {
        const template = req.ips[0]
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(template, { title: "Title" })
    });

    // http://localhost:3000/traversal/express-lfr/10
    /*
    curl --location 'http://localhost:3000/traversal/express-lfr/10' \
    --header 'host: index'
    */
    app.get("/traversal/express-lfr/10", async (req, res) => {
        const template = req.hostname
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(template, { title: "Title" })
    });

    // http://localhost:3000/traversal/express-lfr/10
    /*
    curl --location 'http://localhost:3000/traversal/express-lfr/10' \
    --header 'host: index.index.index'
    */
    app.get("/traversal/express-lfr/11", async (req, res) => {
        const template = req.subdomains[0]
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(template, { title: "Title" })
    });

     // http://localhost:3000/traversal/express-lfr/12
    /*
    curl --location 'http://localhost:3000/traversal/express-lfr/12' \
    --header 'Content-Type: application/json' \
    --data '{
        "file": "index"
    }'
    */
    app.post("/traversal/express-lfr/12", async (req, res) => {
        const template = req.body.file
        // // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(template, { title: "Title" })
    });

    // http://localhost:3000/traversal/express-lfr/13/index
    app.get('/traversal/express-lfr/13/:file', async (req, res) => {
        const template = req.params.file
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(template, { title: "Title" })
    });

    // http://localhost:3000/traversal/express-lfr/14/index/index?file=index
    app.use('/traversal/express-lfr/14/index', async (req, res) => {
        const template = req.path.substring(1, template.length)
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(template, { title: "Title" })
    });

    // http://localhost:3000/traversal/express-lfr/15/index/index?file=index
    app.use('/traversal/express-lfr/15/index', async (req, res) => {
        const template = req.originalUrl.substring(req.originalUrl.indexOf("=") + 1, req.originalUrl.length)
        // ruleid: rules_lgpl_javascript_traversal_rule-express-lfr
        res.render(template, { title: "Title" })
    });
}