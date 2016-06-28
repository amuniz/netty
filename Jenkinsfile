node ('docker && linux') {
  checkout([$class: 'GitSCM', branches: [[name: '*/4.1']], gitTool: 'jgit', userRemoteConfigs: [[url: 'https://github.com/amuniz/netty.git']]])
  def M2_HOME = tool 'M3'
  sh "${M2_HOME}/bin/mvn clean install -DskipTests"
}
