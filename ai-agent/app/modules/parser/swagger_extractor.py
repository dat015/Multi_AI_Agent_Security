from typing import List
from app.schemas.api_schema import APIEndpoint, APIParameter, ParsedSpec


class SwaggerExtractor:
    @staticmethod
    def extract_id_from_schema(schema: dict) -> List[str]:
        """Quét sâu vào schema để tìm các trường có khả năng là ID"""
        found_ids = []
        properties = schema.get("properties", {})
        for prop_name, prop_details in properties.items():
            # Nếu là UUID hoặc Integer và không phải là filter phổ biến
            is_uuid = prop_details.get("format") == "uuid"
            is_int = prop_details.get("type") == "integer"
            
            if is_uuid or is_int:
                found_ids.append(prop_name)
        return found_ids\
        
    @staticmethod
    def extract(spec: dict) -> ParsedSpec:
        endpoints: List[APIEndpoint] = []

        paths = spec.get("paths", {})
        components = spec.get("components", {})
        security_schemes = components.get("securitySchemes", {})
        global_security = spec.get("security", [])

        for path, methods in paths.items():
            for method, details in methods.items():

                parameters = []

                # 🔹 Parameters (path, query, header)
                for param in details.get("parameters", []):
                    parameters.append(APIParameter(
                        name=param.get("name"),
                        location=param.get("in"),
                        required=param.get("required", False),
                        type=param.get("schema", {}).get("type")
                    ))

                # 🔹 Lấy Request Body
                # Lấy toàn bộ dict của requestBody thay vì chỉ check True/False
                raw_request_body = details.get("requestBody")

                # Detect auth
                requires_auth = False
                if "security" in details:
                    requires_auth = True
                elif global_security:
                    requires_auth = True

                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    summary=details.get("summary"),
                    parameters=parameters,
                    requires_auth=requires_auth,
                    request_body=raw_request_body,
                    raw_details=details
                )
                print('endpoint', endpoint)

                endpoints.append(endpoint)  

        return ParsedSpec(endpoints=endpoints)