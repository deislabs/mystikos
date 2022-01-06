pipeline {
    agent {
        label 'ACC-1804-DC4'
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
        stage('Build base container') {
            steps {
                dir(env.BASE_DOCKERFILE_DIR) {
                    sh """
                        chmod +x ./build.sh
                        mkdir build
                        cd build
                        ../build.sh -m "${params.MYST_VERSION}" -o "${params.OE_BASE_CONTAINER_TAG}" -u "18.04" -t "${params.MYST_BASE_CONTAINER_TAG}"
                        ../build.sh -m "${params.MYST_VERSION}" -o "${params.OE_BASE_CONTAINER_TAG}" -u "20.04" -t "${params.MYST_BASE_CONTAINER_TAG}"
                    """
                }
            }
        }
        stage('Push base containers to internal repository') {
            when {
                expression { return params.PUBLISH_CONTAINERS }
            }
            steps {
                script {
                    tag_bionic = "mystikos-bionic:${params.MYST_BASE_CONTAINER_TAG}"
                    tag_focal = "mystikos-focal:${params.MYST_BASE_CONTAINER_TAG}"
                    docker.withRegistry(params.INTERNAL_REPO, env.INTERNAL_REPO_CREDS) {
                        base_1804_image = docker.image(tag_bionic)
                        base_2004_image = docker.image(tag_focal)
                        base_1804_image.push()
                        base_2004_image.push()

                        if ( params.MYST_BASE_CONTAINER_TAG != 'latest' ) {
                            base_1804_image.push('latest')
                            base_2004_image.push('latest')
                        }
                    }
                    sh "docker logout"
                }
            }
        }
    }
}
