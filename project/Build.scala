import sbt._
import Keys._

object ScalaOAuth2Build extends Build {

  lazy val _organization = "kairos"
  lazy val _version =  "0.9.0-SNAPSHOT"
  lazy val _playVersion = "2.3.2"

  val _crossScalaVersions = Seq("2.10.3", "2.11.2")
  val _scalaVersion = "2.11.2"

  val commonDependenciesInTestScope = Seq(
    "org.scalatest" %% "scalatest" % "2.2.0" % "test"
  )

  lazy val scalaOAuth2ProviderSettings = Defaults.defaultSettings ++ Seq(
    organization := _organization,
    version := _version,
    scalaVersion := _scalaVersion,
    crossScalaVersions := _crossScalaVersions,
    scalacOptions ++= _scalacOptions,
    publishTo <<= version { (v: String) => _publishTo(v) },
    credentials := _credentials,
    publishArtifact in Test := false,
    pomIncludeRepository := { x => false }
  )

  lazy val root = Project(
    id = "scala-oauth2-provider",
    base = file("."),
    settings = scalaOAuth2ProviderSettings ++ Seq(
      name := "scala-oauth2-provider",
      description := "OAuth 2.0 server-side implementation written in Scala"
    )
  ).aggregate(scalaOAuth2Core, play2OAuth2Provider)

  lazy val scalaOAuth2Core = Project(
    id = "scala-oauth2-core",
    base = file("scala-oauth2-core"),
    settings = scalaOAuth2ProviderSettings ++ Seq(
      name := "scala-oauth2-core",
      description := "OAuth 2.0 server-side implementation written in Scala",
      libraryDependencies ++= Seq(
        "commons-codec" % "commons-codec" % "1.8",
        "com.nimbusds" % "oauth2-oidc-sdk" % "3.3",
        "joda-time" % "joda-time" % "2.3",
        "org.joda" % "joda-convert" % "1.3.1",
        "javax.servlet" % "javax.servlet-api" % "3.0.1"
      ) ++ commonDependenciesInTestScope
    )
  )

  lazy val play2OAuth2Provider = Project(
    id = "play2-oauth2-provider",
    base = file("play2-oauth2-provider"),
    settings = scalaOAuth2ProviderSettings ++ Seq(
      name := "play2-oauth2-provider",
      description := "Support scala-oauth2-core library on Playframework Scala",
      resolvers += "Typesafe repository" at "http://repo.typesafe.com/typesafe/maven-releases/",
      libraryDependencies ++= Seq(
        "com.typesafe.play" %% "play" % _playVersion % "provided"
      ) ++ commonDependenciesInTestScope
    )
  ) dependsOn(scalaOAuth2Core)

  def _publishTo(v: String) = {
    val nexus = "http://is-macmini1.cdlocal:8081/nexus/content/repositories/"
    if (v.trim.endsWith("SNAPSHOT")) Some("snapshots" at nexus + "snapshots")
    else Some("releases" at nexus + "releases")
  }

  val _credentials = Seq(Credentials("Sonatype Nexus Repository Manager", "is-macmini1.cdlocal", "admin", "admin123"))

  val _scalacOptions = Seq("-deprecation", "-unchecked", "-feature")
}

