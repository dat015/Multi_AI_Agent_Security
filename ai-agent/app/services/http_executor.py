# services/http_executor.py
import httpx
import time
import logging
from app.models.api_request_input import APIRequestInput
from app.models.api_response_output import APIResponseOutput

logger = logging.getLogger(__name__)

class HTTPExecutorService:
    def __init__(self, timeout: int = 10, max_response_length: int = 2000):
        self.timeout = timeout
        self.max_response_length = max_response_length # Tránh tràn Context Window của LLM

    async def execute(self, request_data: APIRequestInput) -> APIResponseOutput:
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                response = await client.request(
                    method=request_data.method.upper(),
                    url=request_data.url,
                    headers=request_data.headers,
                    params=request_data.params,
                    json=request_data.data if request_data.method.upper() in ["POST", "PUT", "PATCH"] else None
                )
                
                response_time = (time.time() - start_time) * 1000
                
                body_text = response.text
                if len(body_text) > self.max_response_length:
                    body_text = body_text[:self.max_response_length] + "\n...[TRUNCATED FOR LLM]"

                return APIResponseOutput(
                    status_code=response.status_code,
                    response_time_ms=round(response_time, 2),
                    headers=dict(response.headers),
                    body=body_text
                )
                
        except httpx.TimeoutException as e:
            logger.warning(f"Timeout khi gọi {request_data.url}: {str(e)}")
            return self._build_error_response("Timeout Exception", start_time)
            
        except httpx.RequestError as e:
            logger.error(f"Lỗi kết nối khi gọi {request_data.url}: {str(e)}")
            return self._build_error_response(f"Request Error: {str(e)}", start_time)
            
        except Exception as e:
            logger.exception(f"Lỗi không xác định: {str(e)}")
            return self._build_error_response(f"Unexpected Error: {str(e)}", start_time)

    def _build_error_response(self, error_msg: str, start_time: float) -> APIResponseOutput:
        return APIResponseOutput(
            status_code=0,
            response_time_ms=round((time.time() - start_time) * 1000, 2),
            headers={},
            body="",
            is_error=True,
            error_message=error_msg
        )