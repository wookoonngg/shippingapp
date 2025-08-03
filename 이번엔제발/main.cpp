#include <iostream>
#include <vector>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cstring>

using namespace std;

// 해시함수 내가 입력한 문자열을 16진수로 바꾸는 역할 
// SHA-256 에 들어가는 상수를 unit32_t에 배열로 넣음 const로 묶어서 수정불가
const uint32_t k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// rotr 함수: 회전 연산 함수 >> 32비트 정수를 오른쪽으로 n비트 회전
inline uint32_t rotr(uint32_t x, unsigned int n) {
    return (x >> n) | (x << (32 - n));
}

// sha-256 압축 함수
void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    // w배열 만들어서 여기에 각각 문자 집어넣음
    for (int i = 0; i < 16; ++i) {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
    }

    // i 16칸으로 w 배열에 16자리 들어가게 계산
    // 처음 16개는 w블록에서 직접 가져옴

    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;

    // state 배열 에 a부터 h까지 값을 더해서 업데이트
}

// 해시함수를 stirng으로 전환하는 함수
// 이게 최종적으로 해시 문자열을 반환하는 것임

string sha256(const string& str) {
    static const char hex_chars[] = "0123456789abcdef";
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // 계산 과정 : 메시지 길이 자체를 비트단위로 추가
    vector<uint8_t> padded_message;
    size_t original_byte_len = str.size();
    size_t original_bit_len = original_byte_len * 8;

    padded_message.reserve(((original_byte_len + 8) / 64 + 1) * 64);
    for (char c : str) {
        padded_message.push_back(static_cast<uint8_t>(c));
    }
    padded_message.push_back(0x80);
    while ((padded_message.size() % 64) != 56) {
        padded_message.push_back(0x00);
    }

    for (int i = 0; i < 8; ++i) {
        padded_message.push_back((original_bit_len >> ((7 - i) * 8)) & 0xFF);
    }

    // 위에 압축함수 호출해서 64바이트 블록 단위로 해시 계산
    for (size_t i = 0; i < padded_message.size(); i += 64) {
        sha256_compress(state, padded_message.data() + i);
    }

    // state 배열의 값을 최종적으로 16진수로 출력
    ostringstream result;
    for (auto value : state) {
        result << hex_chars[(value >> 28) & 0x0F];
        result << hex_chars[(value >> 24) & 0x0F];
        result << hex_chars[(value >> 20) & 0x0F];
        result << hex_chars[(value >> 16) & 0x0F];
        result << hex_chars[(value >> 12) & 0x0F];
        result << hex_chars[(value >> 8) & 0x0F];
        result << hex_chars[(value >> 4) & 0x0F];
        result << hex_chars[value & 0x0F];
    }

    return result.str();
}

/* Block class : 각 블록을 만드는 클래스
   - 블록 생성자 >> 인수로 인덱스, 걸린시간, 블록 데이터(벡터 배열로 걍 넣어버림) 이전 해시, 증명
   - 해시 계산 함수 >> 위에서 짠 sha 256 으로 계산 -> 벡터 내용 압축? 해서 진수로 반환
 */

class Block {
private:
    int index ; // 블록의 인덱스 (블록 번호라 생각 
    time_t timestamp;  // 블록 생성 시간 (채굴과정 시 필요할 듯
    vector<string> data;  // 블록의 데이터
    string previous_hash;  // 이전 블록의 해시
    string hash;  // 현재 블록의 해시
    int proof;  // 작업 증명 값

public:
    // 블록 생성자 
    Block(int idx, time_t ts, const vector<string>& d, const string& prev_hash, int prf)
        : index(idx), timestamp(ts), data(d), previous_hash(prev_hash), proof(prf) {
        hash = calculate_hash();  // 블록 생성 시 해시 계산
    }

    // 블록의 내용을 해시 계산 (해시함수 string으로 해
    string calculate_hash() const {
        stringstream ss;
        ss << index << timestamp << previous_hash << proof;
        for (const auto& d : data) {
            ss << d;
        }
        return sha256(ss.str());
    }

    
    int get_index() const { return index; } // 인덱스 반환
    time_t get_timestamp() const { return timestamp; } // 걸린 시간 반환
    vector<string> get_data() const { return data; } // 사용자가 입력한 정보 반환
    string get_previous_hash() const { return previous_hash; } // 이전해시함수 반환
    string get_hash() const { return hash; } // 이게 현재 해시 ^ 다음 블록의 암호가 되는 
    int get_proof() const { return proof; } // 작업증명
};


/* Blockchain class : 위에 클래스에서 만든 각 블록을 ㄹㅇ 체인으로 이어주는 class
   - block type의 벡터 배열 생성 : 여기에 입력 데이터 저장한다
   - 실시간으로 입력되는 데이터는 따로 받아서 저장
   - 처음 생성되는 블록 = 제네시스 블록 >> 이거의 해시값은 그냥 제공 
   - 새로운 블록 생성자는 Block class로 여기에서 그냥 변수 받아서 씀*/

class Blockchain {
private:
    vector<Block> chain;  // Block 클래스를 type으로 설정해서 block에 저장한 데이터를 이 벡터로 이어
    vector<string> current_data;  // 새로운 블럭에 들어갈 애를 벡터에

public:
    // 블록체인 생성자 (제네시스 블록 추가)
    Blockchain() {
        chain.push_back(create_block(100, "1"));
        // 제네시스 블록의 해시값을 출력하여 확인
        cout << "제네시스 블록 해시: " << chain[0].get_hash() << endl << endl;

        // 위에 sha 256에서 chain 첫번째 칸에 들어간 데이터를 그냥 여기서 출력 >> 사용자는 그냥 그거 복붙하면 풀림
    }

    // 이게 새로운 블럭 만드는 함수 type block으로 해서 변수 돌려씀 ;
    Block create_block(int proof, const string& previous_hash) {
        time_t current_time;
        time(&current_time); // 지금 시간 참조해서 걸린 시간을 위에서 뺌 
        Block block(chain.size() + 1, current_time, current_data, previous_hash, proof); // size에 1더해서 목록 수? 한 개 씩 커지게, 시간, 블록 데이터, 이전 함수까지 입력 이게 벡터에 들어가게하자
        current_data.clear();  // 블록체인에 정보가 들어가면 current_data값은 초기화
        chain.push_back(block); // block 객체에 current_data 함수에서 들어간 내용을 새 블록으로 넣은 거임
        return block;
    }

    // add 함수에서 데이터 입력
    // Blockchain 클래스 내 add_data 수정
    void add_data(const string& buyer, const string& seller, const string& product, const string& price,
        const string& old_fee, const string& blockchain_fee) {
        current_data.push_back("Buyer: " + buyer);
        current_data.push_back("Seller: " + seller);
        current_data.push_back("Product: " + product);
        current_data.push_back("Price: " + price);
        current_data.push_back("Old Transaction Fee: " + old_fee);
        current_data.push_back("Blockchain Transaction Fee: " + blockchain_fee);
    }


    // 체인의 마지막 블록 반환
    Block last_block() const {
        return chain.back();
    }

    // 작업 증명 함수 : 이전 해시랑 맞는 지 안 맞는지 확인
    int proof_of_work(int last_proof) const {
        int proof = 0;
        while (!valid_proof(last_proof, proof)) {
            proof++;
        }
        return proof;
    }

    // 증명의 유효성을 확인 (해시의 접두사가 "0000"인지 확인)
    bool valid_proof(int last_proof, int proof) const {
        string guess = to_string(last_proof) + to_string(proof); //last_proof와 proof 문자열로(to_string)        
        string guess_hash = sha256(guess); //두개 문자열 반환한걸 합쳐서 해시 값으로 변환
        return guess_hash.substr(0, 4) == "0000"; // 그 해시값의 접두사가 0000인지 확인
    }
};


// main 함수 수정
int main() {
    Blockchain blockchain;

    string previous_hash;
    string buyer, seller, product, price, old_fee, blockchain_fee;

    while (true) {
        string last_block_hash = blockchain.last_block().get_hash();

        cout << "이전 블록의 해시를 입력하세요 : ";
        cin >> previous_hash;

        if (previous_hash != last_block_hash) {
            cout << "이전 블록의 해시가 일치하지 않습니다. 다시 시도하세요.\n";
            continue;
        }

        cin.ignore();
        cout << "\n[거래 정보 입력 시작]\n";

        cout << "구매자 이름: ";
        getline(cin, buyer);
        cout << "판매자 이름: ";
        getline(cin, seller);
        cout << "거래 상품: ";
        getline(cin, product);
        cout << "거래 금액 (예: 10000원): ";
        getline(cin, price);
        cout << "기존 중개 거래비용 (예: 1000원): ";
        getline(cin, old_fee);
        cout << "블록체인 거래비용 (예: 10원): ";
        getline(cin, blockchain_fee);

        blockchain.add_data(buyer, seller, product, price, old_fee, blockchain_fee);

        Block last_block = blockchain.last_block();
        int last_proof = last_block.get_proof();
        int proof = blockchain.proof_of_work(last_proof);

        Block new_block = blockchain.create_block(proof, last_block.get_hash());

        cout << "\n==================== 거래 체결 완료 ====================\n";
        cout << "블록 인덱스: " << new_block.get_index() << endl;
        cout << "생성 시간: " << new_block.get_timestamp() << endl;
        cout << "블록 해시: " << new_block.get_hash() << endl;
        cout << "이전 해시: " << new_block.get_previous_hash() << endl;
        cout << ">> 거래 체결 내용:\n";

        for (const auto& item : new_block.get_data()) {
            cout << " - " << item << endl;
        }

        // 거래비용 비교 출력
        cout << "\n💰 기존 거래비용: " << old_fee << " → 블록체인 거래비용: " << blockchain_fee << endl;
        cout << "✅ 비용 절감 효과가 명확합니다!\n";
        cout << "=======================================================\n\n";
    }

    return 0;
}




/*
[proof_of_work 작업 증명 함수]

<목적>
- 새 블록 추가할 때 요구되는 계산 작업
- 블록체인 공격방어, 네트워크 보안 강화 ,, 즉 보안성을 나타내는 함수 코드

< 작업증명 원리>
- 결론적으로는 해시값을 찾는 함수임 
- 보통 이 해시값 비교는 해시값의 접두사 (보통 0000)를 통해서 
- 이 해시값을 찾는 과정이 네트워크 난이도? 를 결정 그래서 timestamp 만든거임
- 해시값을 만들 때는 블록에 있는 내용을 기반으로 해시값을 계산해야하는데 이때 작업 증명값= 넌스를 시도
- 해시값을 만들고 블록이 요구하는 조건이랑 안 맞으면 계속 시도 = 넌스 (none)를 계속 맞추는거임

<코드상 작업 증명>
- proof 변수 0으로 초기화
- valid_proof 함수 : last_proof, proof 문자열로 변환해서 결합 -> sha256으로 해시 계산 -> 해시값 접두사 비교
- valid_proof 함수 통해 현재 proof 값 유효한 지 확인 -> 유효하지 않으면 proof 값 1 올림

*/




/* <의논할 바>
1. 입력 정보 추가할게 있는가
2. 이전 해시함수를 비밀키로 둘 것인가 공개할지 말지 현재 코드는 공개되어 있음
3. timestamp 사용으로 채굴도 가능함 이걸 발전 시켜서 토큰발행이나 투자 유치 가능
4. ..
*/