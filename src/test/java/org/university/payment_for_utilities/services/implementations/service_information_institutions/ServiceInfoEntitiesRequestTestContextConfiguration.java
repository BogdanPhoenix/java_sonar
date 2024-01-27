package org.university.payment_for_utilities.services.implementations.service_information_institutions;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.*;
import org.university.payment_for_utilities.configurations.database.DataBaseConfiguration;
import org.university.payment_for_utilities.domains.service_information_institutions.Edrpou;
import org.university.payment_for_utilities.domains.service_information_institutions.PhoneNum;
import org.university.payment_for_utilities.domains.service_information_institutions.UnitMeasurement;
import org.university.payment_for_utilities.domains.service_information_institutions.Website;
import org.university.payment_for_utilities.pojo.requests.service_information_institutions.EdrpouRequest;
import org.university.payment_for_utilities.pojo.requests.service_information_institutions.PhoneNumRequest;
import org.university.payment_for_utilities.pojo.requests.service_information_institutions.UnitMeasurementRequest;
import org.university.payment_for_utilities.pojo.requests.service_information_institutions.WebsiteRequest;

import static org.university.payment_for_utilities.AdditionalTestingTools.createEntity;

@TestConfiguration
@ComponentScan(basePackages = "org.university.payment_for_utilities.services.implementations.service_information_institutions")
@Import(DataBaseConfiguration.class)
public class ServiceInfoEntitiesRequestTestContextConfiguration {
    @Autowired
    private WebsiteServiceImpl websiteService;
    @Autowired
    private EdrpouServiceImpl edrpouService;
    @Autowired
    private UnitMeasurementServiceImpl unitMeasurementService;
    @Autowired
    private PhoneNumServiceImpl phoneNumService;

    @Lazy
    @Bean(name = "companyPhoneNum")
    public PhoneNum companyPhoneNum(){
        var request = companyPhoneNumRequest();
        return createPhoneNum(request);
    }

    @Lazy
    @Bean(name = "companyPhoneNumRequest")
    public PhoneNumRequest companyPhoneNumRequest(){
        return PhoneNumRequest
                .builder()
                .number("380496321573")
                .build();
    }

    @Lazy
    @Bean(name = "bankPhoneNum")
    public PhoneNum bankPhoneNum(){
        var request = bankPhoneNumRequest();
        return createPhoneNum(request);
    }

    @Lazy
    @Bean(name = "bankPhoneNumRequest")
    public PhoneNumRequest bankPhoneNumRequest(){
        return PhoneNumRequest
                .builder()
                .number("380496321563")
                .build();
    }

    @Lazy
    @Bean(name = "updateBankPhoneNum")
    public PhoneNum updateBankPhoneNum(){
        var request = updateBankPhoneNumRequest();
        return createPhoneNum(request);
    }

    @Lazy
    @Bean(name = "updateBankPhoneNumRequest")
    public PhoneNumRequest updateBankPhoneNumRequest(){
        return PhoneNumRequest
                .builder()
                .number("380452136521")
                .build();
    }

    @Lazy
    @Bean(name = "unitKilowatt")
    public UnitMeasurement unitKilowatt(){
        return createUnitMeasurement(unitKilowattRequest());
    }

    @Lazy
    @Bean(name = "unitCubicMeter")
    public UnitMeasurement unitCubicMeter(){
        return createUnitMeasurement(unitCubicMeterRequest());
    }

    @Lazy
    @Bean(name = "unitKilowattRequest")
    public UnitMeasurementRequest unitKilowattRequest(){
        return UnitMeasurementRequest
                .builder()
                .uaName("кіловат")
                .enName("kilowatt")
                .build();
    }

    @Lazy
    @Bean(name = "unitCubicMeterRequest")
    public UnitMeasurementRequest unitCubicMeterRequest(){
        return UnitMeasurementRequest
                .builder()
                .uaName("куб. м.")
                .enName("cubic meter")
                .build();
    }

    @Lazy
    @Bean(name = "privateBankWebsite")
    public Website privateBankWebsite(){
        return createWebsite(privateBankWebsiteRequest());
    }

    @Lazy
    @Bean(name = "privateBankWebsiteRequest")
    public WebsiteRequest privateBankWebsiteRequest(){
        return WebsiteRequest
                .builder()
                .value("https://privatbank.ua/")
                .build();
    }

    @Lazy
    @Bean(name = "raiffeisenBankWebsite")
    public Website raiffeisenBankWebsite(){
        return createWebsite(raiffeisenBankWebsiteRequest());
    }

    @Lazy
    @Bean(name = "raiffeisenBankWebsiteRequest")
    public WebsiteRequest raiffeisenBankWebsiteRequest(){
        return WebsiteRequest
                .builder()
                .value("https://raiffeisen.ua/")
                .build();
    }

    @Lazy
    @Bean(name = "privateBankEdrpou")
    public Edrpou privateBankEdrpou(){
        return createEdrpou(privateBankEdrpouRequest());
    }

    @Lazy
    @Bean(name = "privateBankEdrpouRequest")
    public EdrpouRequest privateBankEdrpouRequest(){
        return EdrpouRequest
                .builder()
                .value("14360570")
                .build();
    }

    @Lazy
    @Bean(name = "raiffeisenBankEdrpou")
    public Edrpou raiffeisenBankEdrpou(){
        return createEdrpou(raiffeisenBankEdrpouRequest());
    }

    @Lazy
    @Bean(name = "raiffeisenBankEdrpouRequest")
    public EdrpouRequest raiffeisenBankEdrpouRequest(){
        return EdrpouRequest
                .builder()
                .value("14305909")
                .build();
    }

    @Lazy
    @Bean(name = "kyivEdrpou")
    public Edrpou kyivEdrpou(){
        return createEdrpou(kyivEdrpouRequest());
    }

    @Lazy
    @Bean(name = "kyivEdrpouRequest")
    public EdrpouRequest kyivEdrpouRequest(){
        return EdrpouRequest
                .builder()
                .value("14305919")
                .build();
    }

    @Lazy
    @Bean(name = "raiffeisenBankUpdateEdrpou")
    public Edrpou raiffeisenBankUpdateEdrpou(){
        return createEdrpou(raiffeisenBankUpdateEdrpouRequest());
    }

    @Lazy
    @Bean(name = "raiffeisenBankUpdateEdrpouRequest")
    public EdrpouRequest raiffeisenBankUpdateEdrpouRequest(){
        return EdrpouRequest
                .builder()
                .value("14380701")
                .build();
    }

    private PhoneNum createPhoneNum(PhoneNumRequest request){
        return (PhoneNum) createEntity(phoneNumService, request);
    }

    private UnitMeasurement createUnitMeasurement(UnitMeasurementRequest request){
        return (UnitMeasurement) createEntity(unitMeasurementService, request);
    }

    private Website createWebsite(WebsiteRequest request){
        return (Website) createEntity(websiteService, request);
    }

    private Edrpou createEdrpou(EdrpouRequest request){
        return (Edrpou) createEntity(edrpouService, request);
    }
}
