from app.modules.parser.swagger_parser import SwaggerParser
from app.security.security_analyzer import SecurityAnalyzer
from app.modules.agent.agent import AIAgent
from app.core.constants import SWAGGER_DEFAULT_PATH
from app.modules.parser.swagger_extractor import SwaggerExtractor

def main():
    # 1. Parse (Resolving các $ref)
    spec = SwaggerParser.parse(SWAGGER_DEFAULT_PATH)

    # 2. Extract (Lấy Metadata chi tiết)
    parsed_data = SwaggerExtractor.extract(spec)

    # 3. Static Filter (Giai đoạn 1+2: Giảm 70% Token rác)
    potential_threats = SecurityAnalyzer.analyze(parsed_data.endpoints)

    if potential_threats:
        agent = AIAgent()
        
        # 4. Semantic Normalization (Giai đoạn 3: Dịch code sang convention chung để AI hiểu)
        normalized_data = agent.normalize(potential_threats)
        
        # 5. Expert Audit (Giai đoạn 4: Chỉ soi những thứ đã chuẩn hóa)
        final_analysis = agent.audit(normalized_data)
        
        print(final_analysis)


if __name__ == "__main__":
    main()