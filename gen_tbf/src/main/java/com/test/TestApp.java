package com.test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.pingidentity.oss.unbearable.client.TokenBindingMessageMaker;
import com.pingidentity.oss.unbearable.messages.TokenBinding;
import com.pingidentity.oss.unbearable.messages.TokenBindingKeyParameters;
import com.pingidentity.oss.unbearable.messages.TokenBindingMessage;

public class TestApp {
	public static void main(String[] args) {
		TestApp tc = new TestApp();
	}

	public static TokenBindingMessage fromBase64urlEncoded(String encodedTokenBindingMessage, byte[] ekm)
			throws IOException, GeneralSecurityException {
		byte[] tokenBindingMessageBytes = Base64.getUrlDecoder().decode(encodedTokenBindingMessage);
		return TokenBindingMessage.fromBytes(tokenBindingMessageBytes, ekm);
	}

	public TestApp() {
		try {

			// openssl rsa -in clientjwt.key -pubout -outform DER -out clientjwt_pub.der
			// openssl pkcs8 -topk8 -inform PEM -outform DER -in clientjwt.key -out clientjwt_priv.der -nocrypt

			byte[] pkeyBytes = Files.readAllBytes(Paths.get("../certs/clientjwt_pub.der"));
			X509EncodedKeySpec pspec = new X509EncodedKeySpec(pkeyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(pspec);

			byte[] keyBytes = Files.readAllBytes(Paths.get("../certs/clientjwt_priv.der"));
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			PrivateKey privKey = kf.generatePrivate(spec);

			byte[] ekm = pubKey.getEncoded();

			KeyPair keyPair = new KeyPair(pubKey, privKey);
			TokenBindingMessageMaker maker = new TokenBindingMessageMaker().ekm(ekm)
					.providedTokenBinding(TokenBindingKeyParameters.RSA2048_PKCS1_5, keyPair);
			byte[] tbMsg = maker.makeTokenBindingMessage();

			TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBytes(tbMsg, ekm);
			String encodedEkm = Base64.getUrlEncoder().withoutPadding().encodeToString(ekm);
			System.out.println("EKM: " + encodedEkm);
			System.out.println();
			ekm = Base64.getUrlDecoder().decode(encodedEkm);

			TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
			byte[] opaqueTokenBindingID = provided.getOpaqueTokenBindingID();
			// Base64.Encoder b64encoder = Base64.getUrlEncoder().withoutPadding();
			String encodedTbMessage = maker.makeEncodedTokenBindingMessage();
			System.out.println("Sec-Token-Binding: " + encodedTbMessage);
			System.out.println();

			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] tbhBytes = digest.digest(opaqueTokenBindingID);
			String tbh = Base64.getUrlEncoder().withoutPadding().encodeToString(tbhBytes);
			System.out.println("TBH: " + tbh);

			///  VERIFY:
			// in reality, the ekm is extracted from the TLS session info
			//  and the TBH is read out from the provided JWT
			byte[] tbmBytes = Base64.getUrlDecoder().decode(encodedTbMessage);
			tokenBindingMessage = TokenBindingMessage.fromBytes(tbmBytes, ekm);

		
			System.out.println(tokenBindingMessage.getProvidedTokenBinding().getSignatureResult().getStatus());

		} catch (Exception ex) {
			System.out.println("Error:  " + ex);
		}
	}

}
