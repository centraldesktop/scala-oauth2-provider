package scalaoidc.provider

import play.api.mvc._
import scala.language.implicitConversions
import scala.collection.JavaConversions._
import com.nimbusds.openid.connect.sdk.AuthenticationRequest
import scalaoauth2.provider._
import com.nimbusds.oauth2.sdk.{GeneralException, ParseException}
import com.nimbusds.oauth2.sdk.http.HTTPResponse
import play.api.libs.json.{JsNumber, JsString, Json, JsValue}

/**
 * OIDCProvider supports returning id_token for successful authentication
 *
 * <h3>Create controller for authorization</h3>
 * <code>
 * object OAuth2Controller extends Controller with OIDCProvider {
 *   def idToken = Action { implicit request =>
 *     issueAccessToken(new MyDataHandler())
 *   }
 * }
 * </code>
 *
 * <h3>Register routes</h3>
 * <code>
 * GET /oauth2/authorize controllers.OAuth2Controller.authorize
 * </code>
 */
trait OIDCProvider extends OAuth2Provider {

  def parseRequest(request: RequestHeader): AuthenticationRequest = {
    AuthenticationRequest.parse(request.rawQueryString)
  }

  def parseRequest[A](request: Request[A]): AuthenticationRequest = {
    val param: Map[String, Seq[String]] = getParam(request)
    val queryString = param.map { case (k,v) => k -> v.mkString }

    AuthenticationRequest.parse(queryString)
  }

  protected[scalaoidc] def responseAccessToken(r: OIDCGrantHandlerResult) = {
    Map[String, JsValue](
      "token_type" -> JsString(r.tokenType),
      "access_token" -> JsString(r.accessToken),
      "id_token" -> JsString(r.idToken)
    ) ++ r.scope.map {
      "scope" -> JsString(_)
    } ++ r.expiresIn.map {
      "expires_in" -> JsNumber(_)
    } ++ r.refreshToken.map {
      "refresh_token" -> JsString(_)
    }
  }

  protected[scalaoidc] def responseOAuthErrorJson(e: GeneralException): JsValue = Json.obj(
    "error" -> e.getErrorObject.getCode,
    "error_description" -> e.getErrorObject.getDescription
  )

  protected[scalaoidc] def responseOAuthErrorHeader(e: GeneralException): (String, String) = ("WWW-Authenticate" -> ("Bearer " + toOAuthErrorString(e)))

  protected def toOAuthErrorString(e: GeneralException): String = {
    val params = Seq("error=\"" + e.getErrorObject.getCode + "\"") ++
      (if (!e.getErrorObject.getDescription.isEmpty) { Seq("error_description=\"" + e.getErrorObject.getDescription + "\"") } else { Nil })
    params.mkString(", ")
  }

  /**
   * Issue access token in DataHandler process and return the response to client.
   *
   * @param dataHandler Implemented DataHander for register access token to your system.
   * @param request Playframework is provided HTTP request interface.
   * @tparam A play.api.mvc.Request has type.
   * @return Request is successful then return JSON to client in OAuth 2.0 format.
   *         Request is failed then return BadRequest or Unauthorized status to client with cause into the JSON.
   */
  def issueAuthCode[A, U](dataHandler: DataHandler[U])(implicit request: play.api.mvc.Request[A]): Result = {
    try {
      val oidcRequest = parseRequest(request)
      val response = OIDCAuthorizationEndpoint.handleRequest(oidcRequest, dataHandler)

      Found(response.toURI.toString)
    } catch {
      case e: ParseException => {
        e.getErrorObject.getHTTPStatusCode match {
          case HTTPResponse.SC_BAD_REQUEST         => BadRequest(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
          case HTTPResponse.SC_UNAUTHORIZED        => Unauthorized(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
          case HTTPResponse.SC_FORBIDDEN           => Forbidden(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
          case HTTPResponse.SC_SERVER_ERROR        => InternalServerError(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
          case HTTPResponse.SC_SERVICE_UNAVAILABLE => ServiceUnavailable(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
        }
      }
      case e: OAuthError => {
        if (e.statusCode == 400) BadRequest(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
        else if (e.statusCode == 401) Unauthorized(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
        else ServiceUnavailable(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
      }
    }
  }

  override def tokenEndpoint: TokenEndpoint = {
    OIDCTokenEndpoint
  }
}
