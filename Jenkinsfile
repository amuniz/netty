node ('docker && ubuntu') {
  prepareNode()
  checkout([$class: 'GitSCM', branches: [[name: '*/4.1']], gitTool: 'jgit', userRemoteConfigs: [[url: 'https://github.com/amuniz/netty.git']]])
  def M2_HOME = tool 'M3'
  sh "${M2_HOME}/bin/mvn clean install -DskipTests"
}

def prepareNode() {
  sh 'apt-get -q -y install autoconf'
  sh 'apt-get -q -y install autogen'
  sh 'apt-get -q -y install libtool'
  sh 'apt-get -q -y install default-jdk'
  sh 'apt-get -q -y install git'
  sh 'apt-get -q clean -y && rm -rf /var/lib/apt/lists/* && rm -f /var/cache/apt/*.bin'
}