// License: GNU Lesser General Public License v3.0
// source (original): https://github.com/ajinabraham/njsscan/blob/master/tests/assets/node_source/true_positives/semantic_grep/dos/layer7_object_dos.js
// hash: e7a0a61
module.exports = function (app) {
    // http://localhost:3000/dos/layer7-object-dos/for-loop/1
    app.post('/dos/layer7-object-dos/for-loop/1', function (req, res) {
        console.log(req)
        var list = req.body.list;
        var someArray = ["foo"]
        var start = performance.now()

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        for (let i = 0; i <= list.length; i++) {
            timeoutFunction(performance.now());
        }

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        for (let i = 0; i <= someArray.length; i++) {
            timeoutFunction(performance.now());
        }

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        for (let i = 0; i <= list.slice(0, 1).length; i++) {
            timeoutFunction(performance.now());
        };

        var end = performance.now()

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        for (let i = 0; i <= somearray.length; i++) {
          var len = Object.Keys(list).length;
          busyFunction(performance.now());
        }
        const timeTaken = end - start;
        res.send('Time taken: ' + timeTaken + ' milliseconds')
    });

    // http://localhost:3000/dos/layer7-object-dos/for-loop/2
    app.post('/dos/layer7-object-dos/for-loop/2', function (req, res) {
        var list = req.body.list;
        var start = performance.now()

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        for (let i = 0; i <= list.length; i++) {
            timeoutFunction(performance.now());
        }

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        for (let i = 0; i <= 10; i++) {
            var len = list.length
            timeoutFunction(performance.now());
        }

        var end = performance.now()
        const timeTaken = end - start;
        res.send('Time taken: ' + timeTaken + ' milliseconds')
    });

    // http://localhost:3000/dos/layer7-object-dos/forEach/1
    app.post('/dos/layer7-object-dos/forEach/1', function (req, res) {
        var list = req.body.list;
        var start = performance.now()

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.forEach(element => {
            timeoutFunction(performance.now());
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        ["foo", "bar"].forEach(element => {
            var len = list.length;
            timeoutFunction(performance.now());
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.slice(0, 1).forEach(element => {
            timeoutFunction(performance.now());
            return element;
        });

        var end = performance.now()
        const timeTaken = end - start;
        res.send('Time taken: ' + timeTaken + ' milliseconds')
    });

    // http://localhost:3000/dos/layer7-object-dos/forEach/2
    app.post('/dos/layer7-object-dos/forEach/2', function (req, res) {
        var start = performance.now()
        var someArray = ["foo"]

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        Object.keys(req.body.list).forEach(element => {
            timeoutFunction(performance.now());
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        someArray.forEach(element => {
            var len = req.body.list.length
            timeoutFunction(performance.now());
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        Object.keys(req.body.list).slice(0, 1).forEach(element => {
            timeoutFunction(performance.now());
            return element;
        });

        var end = performance.now()
        const timeTaken = end - start;
        res.send('Time taken: ' + timeTaken + ' milliseconds')
    });

    // http://localhost:3000/dos/layer7-object-dos/map/1
    app.post('/dos/layer7-object-dos/map/1', function (req, res) {
        var start = performance.now()
        console.log(start)

        list = req.body.list

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.map(element => {
            timeoutFunction(performance.now());
            return element;
        });
        
        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        req.body.list.map(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        ["foo", "bar"].map(element => {
            var len = req.body.list.length;
            timeoutFunction(performance.now());
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.slice(0, 1).map(element => {
            timeoutFunction(performance.now());
            return element;
        });

        var end = performance.now()
        const timeTaken = end - start;   
        res.send('Time taken: ' + timeTaken + ' milliseconds')
    });

    
    // http://localhost:3000/dos/layer7-object-dos/map/2
    app.post('/dos/layer7-object-dos/map/2', function (req, res) {
        var start = performance.now()
        var someArray = ["foo"]

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        Object.keys(req.body.list).map(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        Object.keys(someArray).map(element => {
            var len = bodyObj.list.length;
            timeoutFunction(performance.now());
            return element;
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        Object.keys(req.body.list).slice(0, 1).map(element => {
            var len = bodyObj.list.length;
            timeoutFunction(performance.now());
            return element;
        });

        var end = performance.now()
        const timeTaken = end - start;
        res.send('Time taken: ' + timeTaken + ' milliseconds')
    });

    // http://localhost:3000/dos/layer7-object-dos/filter/1
    app.post('/dos/layer7-object-dos/filter/1', function (req, res) {
        var bodyObj = {}
        bodyObj = Object.assign(req.body, {})
        var start = performance.now()
        var list = req.body.list;

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        Object.keys(list).filter(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        bodyObj.list.filter(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        ["foo", "bar"].filter(element => {
            var len = bodyObj.list.length;
            timeoutFunction(performance.now());
            return element;
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.slice(0, 1).filter(element => {
            var len = bodyObj.list.length;
            timeoutFunction(performance.now());
            return element;
        });

        var end = performance.now()
        const timeTaken = end - start;
        res.send('Time taken: ' + timeTaken + ' milliseconds')
    });

    // http://localhost:3000/dos/layer7-object-dos/reduce/1
    app.post('/dos/layer7-object-dos/reduce/1', function (req, res) {
        var bodyObj = {}
        bodyObj = Object.assign(req.body, {})
        var start = performance.now()
        var sampleArr = ["foo", "bar"] 
        var list = req.body.list;

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        Object.keys(list).reduce(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        bodyObj.list.reduce(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        sampleArr.reduce(element => {
            var len = bodyObj.list.length;
            timeoutFunction(performance.now());
            return element;
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.slice(0, 1).reduce((acc, element) => {
            var len = bodyObj.list.length;
            timeoutFunction(performance.now());
            return element;
        });

        var end = performance.now()
        const timeTaken = end - start;
        res.send('Time taken: ' + timeTaken + ' milliseconds')
    });

     // http://localhost:3000/dos/layer7-object-dos/reduce-right/1
     app.post('/dos/layer7-object-dos/reduce-right/1', function (req, res) {
        var bodyObj = {}
        bodyObj = Object.assign(req.body, {})
        var start = performance.now()
        var list = req.body.list;

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        Object.keys(list).reduceRight(element => {
            timeoutFunction(performance.now());
            return element;
        })

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        bodyObj.list.reduceRight(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        [].list.reduceRight(element => {
            var len = bodyObj.list.length;
            timeoutFunction(performance.now());
            return element;
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.slice(0, 1).reduceRight((acc, element) => {
            var len = bodyObj.list.length;
            timeoutFunction(performance.now());
            return element;
        });

        var end = performance.now()
        const timeTaken = end - start;
        res.send('Time taken: ' + timeTaken + ' milliseconds')
    });

    app.post('/dos/layer7-object-dos/slice-sanitize/1', function (req, res) {
        console.log(req)
        var list = req.body.list;
        var start = performance.now()

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.map(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ok: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.slice(0,1).map(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.slice(0).map(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.slice(list.length).map(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.slice(0, list.length).map(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.slice(Object.keys(list).length).map(element => {
            timeoutFunction(performance.now());
            return element;
        });

        // ruleid: rules_lgpl_javascript_dos_rule-layer7-object-dos
        list.slice(0, Object.keys(list).length).map(element => {
            timeoutFunction(performance.now());
            return element;
        });
        

        var end = performance.now()
        const timeTaken = end - start;
        res.send('Time taken: ' + timeTaken + ' milliseconds')
    });


    const timeoutFunction = (lst) => 
    {
        while (performance.now() - lst < 1000) {
            var tem = 100;
        }
    }
}