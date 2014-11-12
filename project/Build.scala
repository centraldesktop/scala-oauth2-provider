import sbt._
import Keys._
import ohnosequences.sbt.SbtS3Resolver._  
import com.amazonaws.services.s3.model.Region  

object ScalaOAuth2Build extends Build {

  lazy val _organization = "kairos"
  lazy val _version =  "0.11.1"
  lazy val _playVersion = "2.3.3"

  val _crossScalaVersions = Seq("2.10.3", "2.11.2")
  val _scalaVersion = "2.10.4"

  val commonDependenciesInTestScope = Seq(
    "org.scalatest" %% "scalatest" % "2.2.0" % "test"
   
  )

  lazy val scalaOAuth2ProviderSettings = Defaults.defaultSettings ++ S3Resolver.defaults ++ Seq(
    organization := _organization,
    version := _version,
    scalaVersion := _scalaVersion,
    crossScalaVersions := _crossScalaVersions,
    scalacOptions ++= _scalacOptions,
    publishMavenStyle := false,
    s3region := Region.US_Standard,
    publishTo := {  
      val prefix = if (isSnapshot.value) "snapshots" else "releases"

      Some(s3resolver.value(s"$prefix s3 bucket", s3("jaroop-" + prefix)) withIvyPatterns)
    },
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
        "com.nimbusds" % "oauth2-oidc-sdk" % "3.4.1",
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
      resolvers += "Era7 maven releases" at "http://releases.era7.com.s3.amazonaws.com",
      libraryDependencies ++= Seq(
        "com.typesafe.play" %% "play" % _playVersion % "provided"
      ) ++ commonDependenciesInTestScope
    )
  ) dependsOn(scalaOAuth2Core)


  val _scalacOptions = Seq("-deprecation", "-unchecked", "-feature")
}
