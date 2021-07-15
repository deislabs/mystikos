FROM vtikoo/cpython:3.8-ubuntu as build
FROM ubuntu:18.04

COPY --from=build /cpython /cpython
#Copy test lists
COPY tests.* /