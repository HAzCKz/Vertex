#!/bin/bash

for i in {1..8}
do
    echo "Execução $i de 8"
    npm run bench:all
done
