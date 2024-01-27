package org.university.payment_for_utilities.services.implementations.address;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.*;
import org.university.payment_for_utilities.configurations.database.DataBaseConfiguration;
import org.university.payment_for_utilities.domains.address.AddressResidence;
import org.university.payment_for_utilities.domains.address.Settlement;
import org.university.payment_for_utilities.domains.address.SettlementName;
import org.university.payment_for_utilities.domains.address.TypeSettlement;
import org.university.payment_for_utilities.pojo.requests.address.*;

import static org.university.payment_for_utilities.AdditionalTestingTools.createEntity;

@TestConfiguration
@ComponentScan(basePackages = "org.university.payment_for_utilities.services.implementations.address")
@Import(DataBaseConfiguration.class)
public class AddressEntitiesRequestTestContextConfiguration {
    @Autowired
    private AddressResidenceServiceImpl addressResidenceService;
    @Autowired
    private TypeSettlementServiceImpl typeService;
    @Autowired
    private SettlementNameServiceImpl nameService;
    @Autowired
    private SettlementServiceImpl settlementService;

    @Lazy
    @Bean(name = "addressKyivResidence")
    public AddressResidence addressKyivResidence(){
        return createAddress(addressKyivRequest());
    }

    @Lazy
    @Bean(name = "addressResidence")
    public AddressResidence addressResidence(){
        return createAddress(addressRivneRequest());
    }

    @Lazy
    @Bean(name = "addressRivneRequest")
    public AddressResidenceRequest addressRivneRequest(){
        var settlement = createSettlement(settlementRivneRequest());

        return AddressResidenceRequest
                .builder()
                .settlement(settlement)
                .uaNameStreet("вулиця")
                .enNameStreet("street")
                .numHouse("5a")
                .numEntrance("1")
                .numApartment("305")
                .build();
    }

    @Lazy
    @Bean(name = "addressKyivRequest")
    public AddressResidenceRequest addressKyivRequest(){
        var settlement = createSettlement(settlementKyivRequest());

        return AddressResidenceRequest
                .builder()
                .settlement(settlement)
                .uaNameStreet("вулиця нова")
                .enNameStreet("new street")
                .numHouse("4")
                .numEntrance("")
                .numApartment("")
                .build();
    }

    @Lazy
    @Bean(name = "settlementKyivRequest")
    public SettlementRequest settlementKyivRequest(){
        var type = createTypeSettlement(typeSettlementVillageRequest());
        var name = createSettlementName(settlementNameKyivRequest());

        return SettlementRequest
                .builder()
                .type(type)
                .zipCode("43265")
                .name(name)
                .build();
    }

    @Lazy
    @Bean(name = "settlementRivneRequest")
    public SettlementRequest settlementRivneRequest(){
        var type = createTypeSettlement(typeSettlementCityRequest());
        var name = createSettlementName(settlementNameRivneRequest());

        return SettlementRequest
                .builder()
                .type(type)
                .zipCode("12345")
                .name(name)
                .build();
    }

    @Lazy
    @Bean(name = "nameRivneRequest")
    public SettlementNameRequest settlementNameRivneRequest(){
        return SettlementNameRequest
                .builder()
                .uaName("Рівне")
                .enName("Rivne")
                .build();
    }

    @Lazy
    @Bean(name = "nameKyivRequest")
    public SettlementNameRequest settlementNameKyivRequest(){
        return SettlementNameRequest
                .builder()
                .uaName("Київ")
                .enName("Kyiv")
                .build();
    }

    @Lazy
    @Bean(name = "typeSettlementCityRequest")
    public TypeSettlementRequest typeSettlementCityRequest(){
        return TypeSettlementRequest
                .builder()
                .uaName("місто")
                .enName("city")
                .build();
    }

    @Lazy
    @Bean(name = "typeSettlementVillageRequest")
    public TypeSettlementRequest typeSettlementVillageRequest(){
        return TypeSettlementRequest
                .builder()
                .uaName("село")
                .enName("village")
                .build();
    }

    @Lazy
    @Bean(name = "oblastRivneRequest")
    public OblastRequest oblastRivneRequest(){
        return OblastRequest
                .builder()
                .uaName("Рівненська")
                .enName("Rivnenska")
                .build();
    }

    @Lazy
    @Bean(name = "oblastKyivRequest")
    public OblastRequest oblastKyivRequest(){
        return OblastRequest
                .builder()
                .uaName("Київська")
                .enName("Kyivska")
                .build();
    }

    @Lazy
    @Bean(name = "districtRivneRequest")
    public DistrictRequest districtRivneRequest(){
        return DistrictRequest
                .builder()
                .uaName("Рівненський")
                .enName("Rivne")
                .build();
    }

    @Lazy
    @Bean(name = "districtBelotserkivskyiRequest")
    public DistrictRequest districtBelotserkivskyiRequest(){
        return DistrictRequest
                .builder()
                .uaName("Білоцерківський")
                .enName("Belotserkivskyi")
                .build();
    }

    private AddressResidence createAddress(AddressResidenceRequest request){
        return (AddressResidence) createEntity(addressResidenceService, request);
    }

    private SettlementName createSettlementName(SettlementNameRequest request){
        return (SettlementName) createEntity(nameService, request);
    }

    private TypeSettlement createTypeSettlement(TypeSettlementRequest request){
        return (TypeSettlement) createEntity(typeService, request);
    }

    private Settlement createSettlement(SettlementRequest request){
        return (Settlement) createEntity(settlementService, request);
    }
}
