package scalaoidc.provider

import play.api.mvc._
import scala.language.implicitConversions
import scala.collection.JavaConversions._
import com.nimbusds.openid.connect.sdk.AuthenticationRequest
import scalaoauth2.provider._
import com.nimbusds.oauth2.sdk.{GeneralException, ParseException}
import play.api.libs.json.{JsNumber, JsString, Json, JsValue}
import scalaoauth2.token.OAuth2AccessTokenResponse
import scalaoidc.token.OIDCIDToken

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

  override val tokenEndpoint: TokenEndpoint = OIDCTokenEndpoint

  def parseRequest(request: RequestHeader): AuthenticationRequest = {
    AuthenticationRequest.parse(request.rawQueryString)
  }

  def parseRequest[A](request: Request[A]): AuthenticationRequest = {
    val param: Map[String, Seq[String]] = getParam(request)
    val queryString = param.map { case (k,v) => k -> v.mkString }

    AuthenticationRequest.parse(queryString)
  }

  override protected def responseAccessToken(r: GrantHandlerResult) = {
    r match {
      case OAuth2GrantHandlerResult(_,_,_,_,_) => (new OAuth2AccessTokenResponse).build(r)
      case OIDCGrantHandlerResult(_,_,_,_,_,_) =>
        new OAuth2AccessTokenResponse[OIDCGrantHandlerResult] with OIDCIDToken[OIDCGrantHandlerResult]
          .build(r.asInstanceOf[OIDCGrantHandlerResult])
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
  def issueAuthCode[A, U](dataHandler: OIDCDataHandler[U], user: U)(implicit request: play.api.mvc.Request[A]): Result = {
    try {
      val oidcRequest = parseRequest(request)
      val response = OIDCAuthorizationEndpoint.handleRequest(oidcRequest, dataHandler, user)

      Found(response.toURI.toString)
    } catch {
      case e: ParseException => {
        Status(e.getErrorObject.getHTTPStatusCode)(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
      }
      case e: OAuthError => {
        Status(e.statusCode)(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
      }
    }
  }
}
