Your submission will be graded by executing the following steps:

```
    tar -xf <your_submission.tgx>
    docker-compose build
    docker-compose up -d
    # running test cases
    docker-compose down
```

You can use the Makefile target "submission" to create your submission archive. 
Furthermore, you can execute "check-submission" to check if your node can be started properly by our grading framework.
Note, however, that "check-submission" will only try to connect to port 18018 on localhost.