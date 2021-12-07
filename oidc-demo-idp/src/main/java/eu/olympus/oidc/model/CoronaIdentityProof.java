package eu.olympus.oidc.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.model.server.rest.IdentityProof;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

public class CoronaIdentityProof extends IdentityProof {
	private String signature;
	private Coronaattributes data;

	public CoronaIdentityProof() {

	}

	public CoronaIdentityProof(JSONObject json) {
		this.signature = json.get("signature").toString();
		try {
			JSONParser parser = new JSONParser();
			JSONObject jData = (JSONObject) parser.parse(json.get("data").toString());
			this.data = new Coronaattributes(jData.get("url:Firstname").toString(),
					(String)jData.get("url:DateOfBirth"),
					jData.get("url:Lastname").toString(),
					jData.get("url:Town").toString());

		} catch (ParseException e) {
			e.printStackTrace();
		}
	}

	public CoronaIdentityProof(String signature, Coronaattributes data) {
		super();
		this.signature = signature;
		this.data = data;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public Coronaattributes getData() {
		return data;
	}

	public void setData(Coronaattributes data) {
		this.data = data;
	}

	@Override
	public String toString() {
		return "SignAPIResponse {" + '\n' +
				"signature (minimized) = " + signature.substring(0, 12) + "," + '\n' +
				"data = "  +'\t' + data + '\n' +
				'}';
	}

	public String toJson() throws JsonProcessingException {
		ObjectMapper mapper = new ObjectMapper();
		return mapper.writeValueAsString(this);
	}
}
