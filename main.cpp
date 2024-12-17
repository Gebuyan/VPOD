#include <iostream>
#include <vector>
#include <random>
#include <iomanip>
#include "seal/seal.h"
#include <ctime>
#include<windows.h>
#include <fstream>
#include <sstream>
using namespace std;
using namespace seal;
using std::endl;
using std::setprecision;

/*生成范围在a,b的随机数*/
double Random(int min,int max) {
    std::random_device rd;
    std::default_random_engine eng(rd());
    std::uniform_real_distribution<> distr(min, max);
    return distr(eng);
}
/*随机生成(m,n)维度的矩阵*/
vector<vector<double>> RandMatrix(int m, int n,int min,int max) {
    std::random_device rd;
    std::default_random_engine eng(rd());
    std::uniform_real_distribution<> distr(min, max);
    vector<vector<double>> Matrix(m, vector<double>(n, 0));
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < n; j++) {
            Matrix[i][j] = distr(eng);
        }
    }
    return Matrix;
}

/*随机生成m或者n维向量*/
vector<double> RandVector(int m, int min, int max) {
    std::random_device rd;
    std::default_random_engine eng(rd());
    std::uniform_real_distribution<> distr(min, max);
    vector<double> Vector(m, 0);
    for (int i = 0; i < m; i++) {
        Vector[i] = distr(eng);
    }
    return Vector;
}

/*直接计算求决策值*/
vector<double> DFC(vector<vector<double>> W,vector<double> x,vector<double> b,int m,int n) {
    
    vector<double> d;
    for (int i = 0; i < m; i++) {
        double temp = 0;
        for (int j = 0; j < n; j++) {
            temp += W[i][j] * x[j];
        }
        temp += b[i];
        d.push_back(temp);
    }
    return d;
}
vector<vector<double>> GetCsvFile(const string& filename) {
    ifstream file(filename);

    if (!file.is_open()) {
        cout << "无法打开文件：" << filename << endl;
        return {};
    }

    vector<vector<double>> data; // 用于存储CSV数据的vector

    string line;
    while (getline(file, line)) {
        vector<double> row;
        istringstream iss(line);
        string field;

        while (getline(iss, field, ',')) { // 假设逗号为CSV文件的分隔符
            row.push_back(stod(field)); // 将字符串转换为double类型
        }

        data.push_back(row);
    }

    file.close();
    return data;
}


int main() {
    /**********************获取模型参数**********************/
    //随机生成一个m*n维度的
    //int m, n;
    //cin >> m >> n;
    //vector<vector<double>> W = RandMatrix(m, n, 1, 10);

    const string filename_w = "data/coefficients.csv";
    vector<vector<double>> W = GetCsvFile(filename_w);
    int m = W.size();
    int n = W[0].size();
    cout << m << "   " << n << endl;
    const string filename_b = "data/intercepts.csv";
    vector<vector<double>> b_data = GetCsvFile(filename_b);
    vector<double> b;
    for (int i = 0; i < m; i++) {
        b.push_back(b_data[i][0]);
    }
    const string filename_test_x = "data/test_x.csv";
    vector<vector<double>> test_x_data = GetCsvFile(filename_test_x);
    const string filename_test_y = "data/test_y.csv";
    vector<vector<double>> test_y_data = GetCsvFile(filename_test_y);
    cout << test_x_data.size()<<endl;
    vector<double> labelAll;
    vector<double> y;
    int flag = 0;
    for (int i = 0; i < test_y_data.size(); i++) {
        y.push_back(test_y_data[i][0]);
        //cout << y[i] << " ";
    }
    //设置初始化
    double T_init = 0, T_request=0,T_DiaOut=0,T_Verify=0,T_dataencrypt = 0, T_DFC = 0, T_classification = 0,T_decode=0;
    for (int t = 0; t < test_x_data.size(); t++) {


     vector<double> x = test_x_data[t];
    /**********************直接计算的时间**********************/
    LARGE_INTEGER nFreq, end, begin;
    QueryPerformanceFrequency(&nFreq);
    QueryPerformanceCounter(&begin);
    vector<double> d;
    for (int i = 0; i < m; i++) {
        double temp = 0;
        for (int j = 0; j < n; j++) {
            temp += W[i][j] * x[j];
        }
        temp += b[i];
        d.push_back(temp);
    }
    QueryPerformanceCounter(&end);
    //cout << "直接计算的Running time: " << (double)(end.QuadPart - begin.QuadPart) / (double)nFreq.QuadPart*1000000 << "us" << endl;

    /**********************Setup**********************/
    LARGE_INTEGER H_init_begin, H_init_end;
    QueryPerformanceCounter(&H_init_begin);
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    double scale = pow(2.0, 40);
    SEALContext context(parms);
    CKKSEncoder encoder(context);
    QueryPerformanceCounter(&H_init_end);
    T_init = (double)(H_init_end.QuadPart - H_init_begin.QuadPart) / (double)nFreq.QuadPart * 1000000;
    if (t == 0) {
        cout << "Setup时间" << T_init << "us" << endl;
    }

    //创建私钥 公钥，重线性化密钥，支持旋转操作密钥
    //医院生成密钥
    LARGE_INTEGER H_keygen_begin, H_keygen_end;
    QueryPerformanceCounter(&H_keygen_begin);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    QueryPerformanceCounter(&H_keygen_end);
    if (t == 0) {
        cout << "HosKeygen时间" << (double)(H_keygen_end.QuadPart - H_keygen_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    }
    
    //用户生成密钥时间
    LARGE_INTEGER P_keygen_begin, P_keygen_end;
    QueryPerformanceCounter(&P_keygen_begin);
    KeyGenerator P_Keygen(context);
    auto P_secret_key = P_Keygen.secret_key();
    PublicKey P_public_key;
    P_Keygen.create_public_key(P_public_key);
    Encryptor P_encryptor(context, P_public_key);
    Decryptor P_decryptor(context, P_secret_key);
    QueryPerformanceCounter(&P_keygen_end);
    if (t == 0) {
        cout<<"PatKeygen时间"<< (double)(P_keygen_end.QuadPart - P_keygen_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    }
    /**********************用户请求生成**********************/
    LARGE_INTEGER User_request_begin, User_request_end;
    QueryPerformanceCounter(&User_request_begin);
    Plaintext pt_x;
    encoder.encode(x, scale, pt_x);
    Ciphertext ct_x;
    encryptor.encrypt(pt_x, ct_x);
    QueryPerformanceCounter(&User_request_end);
    //cout << "用户请求的Running time: " << (double)(User_request_end.QuadPart - User_request_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    T_request += (double)(User_request_end.QuadPart - User_request_begin.QuadPart) / (double)nFreq.QuadPart * 1000000;

    /**********************数据外包**********************/
    //模型W和b外包,可以均摊，不用考虑
    LARGE_INTEGER ModOut_begin, ModOut_end;
    QueryPerformanceCounter(&ModOut_begin);
    Plaintext pt_w, pt_b;
    Ciphertext ct_w, ct_b;
    vector<Ciphertext> ct_W;
    for (int i = 0; i < m; i++) {
        encoder.encode(W[i], scale, pt_w);
        encryptor.encrypt(pt_w, ct_w);
        ct_W.push_back(ct_w);
    }
    encoder.encode(b, scale, pt_b);
    encryptor.encrypt(pt_b, ct_b);
    QueryPerformanceCounter(&ModOut_end);
    if (t == 0) {
        cout << "ModOut时间" << (double)(ModOut_end.QuadPart - ModOut_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    }
    //验证参数
    LARGE_INTEGER DiaOut_begin, DiaOut_end;
    QueryPerformanceCounter(&DiaOut_begin);
    double alpha = 0.01;
    vector<double> beta_1 , beta_2;
    for (int i = 0; i < x.size(); i++) {
        beta_1.push_back(x[i] * alpha);
    }
    for (int i = 0; i < b.size(); i++) {
        beta_2.push_back(b[i] * alpha);
    }
    Plaintext pt_beta_1, pt_beta_2;
    Ciphertext ct_beta_1, ct_beta_2;
    encoder.encode(beta_1, scale, pt_beta_1);
    encryptor.encrypt(pt_beta_1, ct_beta_1);
    encoder.encode(beta_2, scale, pt_beta_2);
    encryptor.encrypt(pt_beta_2, ct_beta_2);
    QueryPerformanceCounter(&DiaOut_end);
    T_DiaOut+= (double)(DiaOut_end.QuadPart - DiaOut_begin.QuadPart) / (double)nFreq.QuadPart * 1000000;
    //    flag = 1;
    //if (flag == 0) {
    //    T_dataencrypt+=(double)(Outsource_end.QuadPart - Outsource_begin.QuadPart) / (double)nFreq.QuadPart * 1000000;
    //    flag = 1;
    //}
    //cout << "外包阶段的Running time: " << (double)(Outsource_end.QuadPart - Outsource_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    /**********************计算阶段**********************/
    LARGE_INTEGER Computate_begin, Computate_end;
    vector<Ciphertext> ct_Temp(m);
    vector<Ciphertext> ct_Temp2(m);
    QueryPerformanceCounter(&Computate_begin);
    for (int i = 0; i < m; i++) {
        vector<double> one_zero(n, 0);
        one_zero[i] = 1;
        Plaintext pt_one_zero; 
        encoder.encode(one_zero,scale, pt_one_zero);
        evaluator.multiply(ct_W[i],ct_x,ct_Temp[i]);
        evaluator.relinearize_inplace(ct_Temp[i], relin_keys);
        size_t poly_modulus_degree_power = log2(poly_modulus_degree);
        Ciphertext ct_rotated;
        for (int j = 0; j < poly_modulus_degree_power - 1; ++j)
        {
            int step = pow(2, j);
            evaluator.rotate_vector(ct_Temp[i], step, gal_keys, ct_rotated);
            evaluator.add_inplace(ct_Temp[i], ct_rotated);
        }
        evaluator.rescale_to_next_inplace(ct_Temp[i]);
        ct_Temp[i].scale() = pow(2.0, 40);
        parms_id_type ct_Wi_parms_id = ct_Temp[i].parms_id();
        evaluator.mod_switch_to_inplace(ct_b, ct_Wi_parms_id);
        evaluator.add_inplace(ct_Temp[i], ct_b);
        evaluator.mod_switch_to_inplace(pt_one_zero, ct_Wi_parms_id);
        evaluator.multiply_plain_inplace(ct_Temp[i], pt_one_zero);
    }

    for (int i = 0; i < m; i++) {
        vector<double> one_zero2(n, 0);
        one_zero2[i] = 1;
        Plaintext pt_one_zero2;
        encoder.encode(one_zero2, scale, pt_one_zero2);
        evaluator.multiply(ct_W[i], ct_beta_1, ct_Temp2[i]);
        evaluator.relinearize_inplace(ct_Temp2[i], relin_keys);
        size_t poly_modulus_degree_power = log2(poly_modulus_degree);
        Ciphertext ct_rotated;
        for (int j = 0; j < poly_modulus_degree_power - 1; ++j)
        {
            int step = pow(2, j);
            evaluator.rotate_vector(ct_Temp2[i], step, gal_keys, ct_rotated);
            evaluator.add_inplace(ct_Temp2[i], ct_rotated);
        }
        evaluator.rescale_to_next_inplace(ct_Temp2[i]);
        ct_Temp2[i].scale() = pow(2.0, 40);
        parms_id_type ct_Wi_parms_id = ct_Temp2[i].parms_id();
        evaluator.mod_switch_to_inplace(ct_beta_2, ct_Wi_parms_id);
        evaluator.add_inplace(ct_Temp2[i], ct_beta_2);
        evaluator.mod_switch_to_inplace(pt_one_zero2, ct_Wi_parms_id);
        evaluator.multiply_plain_inplace(ct_Temp2[i], pt_one_zero2);
    }
    for (int i = 1; i < m; i++) {
        evaluator.add_inplace(ct_Temp[0], ct_Temp[i]);
        evaluator.add_inplace(ct_Temp2[0], ct_Temp2[i]);
    }
    QueryPerformanceCounter(&Computate_end);
    //cout << "安全决策值计算的Running time: " << (double)(Computate_end.QuadPart - Computate_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    T_DFC += (double)(Computate_end.QuadPart - Computate_begin.QuadPart) / (double)nFreq.QuadPart * 1000000;
    /**********************决策值验证**********************/
    LARGE_INTEGER Verfiy_begin, Verfiy_mid, Verfiy_end, find_max_end;


    QueryPerformanceCounter(&Verfiy_begin);
    
    Plaintext pt_d,pt_v;
    decryptor.decrypt( ct_Temp[0],pt_d);
    decryptor.decrypt(ct_Temp2[0], pt_v);
    vector<double> d2,v;
    encoder.decode(pt_d, d2);
    encoder.decode(pt_v, v);
    //int defeatNumber = 0;
    for (int i = 0; i < m; i++) {
        int temp = d2[i] * alpha;
        if (int(v[i]) != int(d2[i] * alpha)) {
            cout << "验证失败" << "                 ";
            cout <<"直接计算的决策值为"<<d[i]<<"       " << "决策值d为：" << d2[i] << "     " << "验证参数为：" << v[i] << endl;
        }
    }
    QueryPerformanceCounter(&Verfiy_end);
    //查找最大决策值
    double maxd = d2[0];
    double label = 0;
    for (int i = 1; i < m; i++) {
        if (d2[i] > maxd) {
            maxd = d2[i];
            label = i;
        }
    }
    labelAll.push_back(label);
    QueryPerformanceCounter(&find_max_end);
    //cout << "解码的Running time: " << (double)(Verfiy_mid.QuadPart - Verfiy_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    //cout << "验证的Running time: " << (double)(Verfiy_end.QuadPart - Verfiy_mid.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    //cout<<"查找最大值的Running time:"<< (double)(find_max_end.QuadPart - Verfiy_end.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    T_Verify += (double)(Verfiy_end.QuadPart - Verfiy_begin.QuadPart) / (double)nFreq.QuadPart * 1000000;
    T_classification += (double)(find_max_end.QuadPart - Verfiy_end.QuadPart) / (double)nFreq.QuadPart * 1000000;
    //医院使用患者密钥加密诊断疾病的标签发送给患者
    LARGE_INTEGER Send_label_begin, Send_label_end;
    QueryPerformanceCounter(&Send_label_begin);
    Plaintext pt_label;
    encoder.encode(label, scale, pt_label);
    Ciphertext ct_label;
    P_encryptor.encrypt(pt_label,ct_label);
    QueryPerformanceCounter(&Send_label_end);
    T_classification += (double)(Send_label_end.QuadPart - Send_label_begin.QuadPart) / (double)nFreq.QuadPart * 1000000;
    //cout << "发送标签给病人的Running time: " << (double)(Send_label_end.QuadPart - Send_label_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;

    //患者使用私钥解密标签
    LARGE_INTEGER Get_label_begin, Get_label_end;
    QueryPerformanceCounter(&Get_label_begin);
    Plaintext pt_result;
    P_decryptor.decrypt(ct_label, pt_result);
    vector<double> result;
    encoder.decode(pt_result, result);
    QueryPerformanceCounter(&Get_label_end);
    //cout << "病人得到标签的Running time: " << (double)(Get_label_end.QuadPart - Get_label_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    T_decode += (double)(Get_label_end.QuadPart - Get_label_begin.QuadPart) / (double)nFreq.QuadPart * 1000000;
    }

    int number = 0;
    double score = 0;
    for (int i = 0; i < labelAll.size(); i++)
    {
        if ((int)labelAll[i] + 1 == (int)y[i])
            number++;
        cout << labelAll[i]<<" ";
    }
    cout << endl << number << endl;
    score = (double)number / (double)labelAll.size();
    cout << "我们的方案VMSOD的准确率为:" << score << endl;
    //cout << "初始化时间：" << T_init << endl;
    
    //cout << "数据加密时间：" << T_dataencrypt << endl;
    cout << "Computate时间：" << T_DFC << endl;
    cout << "Query时间：" << T_classification << endl;
    cout << "request时间" << T_request << endl;
    cout << "DiaOut时间" << T_DiaOut << endl;
    cout << "Decode时间" << T_decode << endl;
    cout << "Verify时间" << T_Verify << endl;
    return 0;
}

