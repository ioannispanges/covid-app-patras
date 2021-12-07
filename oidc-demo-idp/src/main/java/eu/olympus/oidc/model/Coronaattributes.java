package eu.olympus.oidc.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.olympus.util.Util;

public class Coronaattributes {

    @JsonProperty("url:Firstname")
    private String firstname;
    @JsonProperty("url:Lastname")
    private String lastname;
    @JsonProperty("url:DateOfBirth")
    private String dateOfBirth; // RFC compliant
    @JsonProperty("url:Town")
    private String town;


    public Coronaattributes(){}

    public Coronaattributes(String firstname, String lastname,String dateOfBirth, String town) {
        this.firstname = firstname;
        this.dateOfBirth = Util.toRFC3339UTC(Util.fromRFC3339UTC(dateOfBirth));
        this.lastname = lastname;
        this.town = town;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setTown(String town) {
        this.town = town;
    }

    public String getTown() {
        return getTown();
    }


    public String getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(String dateOfBirth) {
        this.dateOfBirth = Util.toRFC3339UTC(Util.fromRFC3339UTC(dateOfBirth));
    }



    @Override
    public String toString() {
        return "Attributes {" + '\n' + '\t' +
                "firstname = " + firstname + "," + '\n' + '\t' +
                "dateOfBirth = " + dateOfBirth + "," + '\n' + '\t' +
                "lastname = " + lastname + "," + '\n' + '\t' +
                "town = " + town + '\n' + '\t' + '}';
    }
}
