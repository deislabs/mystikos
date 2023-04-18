def containers_reqs = [
    'libcxx': ['dir': 'tests/libcxx', 'make': 'libcxx-tests'],
    'libcxx2': ['dir': 'tests/libcxx2', 'make': 'libcxx-tests']
]

def containers_to_build = [
    'aspnetcore5': ['dir': 'tests/aspnetcore5', 'file': 'Dockerfile.aspnet5', buildArgs: [], tag: 'v5.0.11'],
    'aspnetcore6': ['dir': 'tests/aspnetcore6', 'file': 'Dockerfile', buildArgs: [], tag: 'v6.0.0-preview.2.21154.6'],
    'dotnet-sos-prereqs': ['dir': 'tests/dotnet-sos', 'file': 'Dockerfile-prereqs', buildArgs: [], tag: ''],
    'glibc': ['dir': 'tests/glibc', 'file': 'Dockerfile', buildArgs: [], tag: 'release/2.34/master'],
    'libcxx': ['dir': 'tests/libcxx', 'file': 'Dockerfile', buildArgs: [], tag: ''],
    'libcxx2': ['dir': 'tests/libcxx2', 'file': 'Dockerfile', buildArgs: [], tag: ''],
    'azure-python-sdk-storage-blob': ['dir': 'solutions/python_azure_sdk', 'file': 'Dockerfile', 'buildArgs' : ['PACKAGES="keyvault_identity/packages.txt"'], tag: 'azure-storage-blob_12.8.1'],
    'azure-python-sdk-keyvault-identity': ['dir': 'solutions/python_azure_sdk', 'file': 'Dockerfile', 'buildArgs' : ['PACKAGES="storage/packages.txt"'], tag: 'azure-mgmt-keyvault_9.1.0'],
    'azure-python-sdk-storage': ['dir': 'solutions/python_azure_sdk', 'file': 'Dockerfile', 'buildArgs' : ['PACKAGES="storage-blob/packages.txt"'], tag: 'azure-mgmt-storage_19.0.0'],
    'pytorch-test': ['dir': 'solutions/pytorch_tests', 'file': 'Dockerfile', buildArgs: [], tag: 'v1.10.0'],
    'dotnet-lib-5-glibc': ['dir': 'tests/dotnet-lib-5', 'file': 'Dockerfile.glibc', buildArgs: [], tag: 'v5.0.11'],
    'dotnet-lib-5-musl': ['dir': 'tests/dotnet-lib-5', 'file': 'Dockerfile.musl', buildArgs: [], tag: 'v5.0.11'],
    'dotnet-lib-6-glibc': ['dir': 'tests/dotnet-lib-6', 'file': 'Dockerfile.glibc', buildArgs: [], tag: 'v6.0.1'],
]

pipeline {
    agent {
        label 'nonSGX-ubuntu-2004'
    }
    options {
        timeout(time: 360, unit: 'MINUTES')
    }
    parameters {
        string(name: "MYST_VERSION", description: "Mystikos release version (Example: 0.5.0). See https://github.com/deislabs/mystikos/releases for release versions")
        string(name: "REPOSITORY_NAME", defaultValue: "deislabs/mystikos", description: "GitHub repository to checkout")
        string(name: "BRANCH_NAME", defaultValue: "master", description: "The branch used to checkout the repository")
        string(name: "MYST_BASE_CONTAINER_TAG", defaultValue: "latest", description: "The tag for the new Mystikos base Docker container.")
        string(name: "OE_BASE_CONTAINER_TAG", defaultValue: "SGX-2.15.100", description: "The tag for the base OE Docker container. Use SGX-<version> for releases. Example: SGX-2.15.100")
        string(name: "INTERNAL_REPO", defaultValue: "https://mystikos.azurecr.io", description: "Url for internal Docker repository")
        booleanParam(name: "PUBLISH_CONTAINERS", defaultValue: false, description: "Publish container to registry?")
    }
    environment {
        INTERNAL_REPO_CREDS = 'mystikos-internal-container-registry'
        BASE_DOCKERFILE_DIR = ".jenkins/docker/base/"
    }
    stages {
        stage("Checkout") {
            steps {
                cleanWs()
                checkout([$class: 'GitSCM',
                    branches: [[name: BRANCH_NAME]],
                    extensions: [],
                    userRemoteConfigs: [[url: "https://github.com/${params.REPOSITORY_NAME}"]]])
            }
        }
        stage('Build container requirements') {
            steps {
                script {
                    containers_reqs.each { container -> 
                        try {
                            sh """#!/bin/bash
                               cd ${WORKSPACE}/${container.value.dir} && make ${container.value.make}
                               """
                        } catch (Exception e) { sh "echo 'Failed: ${container.key}'"}
                    }
                }
            }
        }
        stage('Build and upload test containers') {
            steps {
                script {
                    containers_to_build.each { container -> 
                        buildArgs = ""
                        container.value.buildArgs.each { arg ->
                          buildArgs += "--build-arg ${arg} "
                        }
                        if (container.value.tag != '') {
                            buildArgs += "--build-arg TAG=\"${container.value.tag}\""
                        }
                        try {
                            sh """#!/bin/bash
                               docker build --no-cache --tag "mystikos/${container.key}" --file "${container.value.dir}/${container.value.file}" ${buildArgs} "${container.value.dir}"
                               """

                            container_tag = "mystikos/${container.key}:${params.MYST_BASE_DOCKER_TAG}"
                            docker.withRegistry(params.INTERNAL_REPO, env.INTERNAL_REPO_CREDS) {
                                test_container = docker.image(container_tag)
                                test_container.push()
                                if ( params.MYST_BASE_CONTAINER_TAG != 'latest' ) {
                                    test_container.push('latest')
                                }
                            }
                            sh "docker logout"
                        } catch (Exception e) { sh "echo 'Failed: ${container.key}'"}
                    }
                }
            }
        }
    }
}
