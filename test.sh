#!/bin/bash


# Build client
cd client

go build

mv gitsec /usr/local/bin/

cd ..

cd gittest

git commit -S -m 'testing stuff'

cd ..
