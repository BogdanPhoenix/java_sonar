package org.university.payment_for_utilities.services.implementations.receipt;

import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.receipt.BlockMeterReading;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.receipt.BlockMeterReadingRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.receipt.BlockMeterReadingResponse;
import org.university.payment_for_utilities.repositories.receipt.BlockMeterReadingRepository;
import org.university.payment_for_utilities.services.implementations.auxiliary_services.CounterSearcherService;
import org.university.payment_for_utilities.services.interfaces.receipt.BlockMeterReadingService;

@Service
public class BlockMeterReadingServiceImpl extends CounterSearcherService<BlockMeterReading, BlockMeterReadingRepository> implements BlockMeterReadingService {
    protected BlockMeterReadingServiceImpl(BlockMeterReadingRepository repository) {
        super(repository, "Blocks meter readings");
    }

    @Override
    protected BlockMeterReading createEntity(Request request) {
        var blockRequest = (BlockMeterReadingRequest) request;
        return BlockMeterReading
                .builder()
                .receipt(blockRequest.getReceipt())
                .prevValueCounter(blockRequest.getPrevValueCounter())
                .currentValueCounter(blockRequest.getCurrentValueCounter())
                .build();
    }

    @Override
    protected BlockMeterReading createEntity(Response response) {
        var builder = BlockMeterReading.builder();
        super.initCounterSearcherBuilder(builder, response);
        return builder.build();
    }

    @Override
    protected Response createResponse(BlockMeterReading entity) {
        var builder = BlockMeterReadingResponse.builder();
        super.initCounterResponseBuilder(builder, entity);
        return builder.build();
    }
}
