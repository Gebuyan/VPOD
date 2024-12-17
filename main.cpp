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

/*���ɷ�Χ��a,b�������*/
double Random(int min,int max) {
    std::random_device rd;
    std::default_random_engine eng(rd());
    std::uniform_real_distribution<> distr(min, max);
    return distr(eng);
}
/*�������(m,n)ά�ȵľ���*/
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

/*�������m����nά����*/
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

/*ֱ�Ӽ��������ֵ*/
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
        cout << "�޷����ļ���" << filename << endl;
        return {};
    }

    vector<vector<double>> data; // ���ڴ洢CSV���ݵ�vector

    string line;
    while (getline(file, line)) {
        vector<double> row;
        istringstream iss(line);
        string field;

        while (getline(iss, field, ',')) { // ���趺��ΪCSV�ļ��ķָ���
            row.push_back(stod(field)); // ���ַ���ת��Ϊdouble����
        }

        data.push_back(row);
    }

    file.close();
    return data;
}


int main() {
    /**********************��ȡģ�Ͳ���**********************/
    //�������һ��m*nά�ȵ�
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
    //���ó�ʼ��
    double T_init = 0, T_request=0,T_DiaOut=0,T_Verify=0,T_dataencrypt = 0, T_DFC = 0, T_classification = 0,T_decode=0;
    for (int t = 0; t < test_x_data.size(); t++) {


     vector<double> x = test_x_data[t];
    /**********************ֱ�Ӽ����ʱ��**********************/
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
    //cout << "ֱ�Ӽ����Running time: " << (double)(end.QuadPart - begin.QuadPart) / (double)nFreq.QuadPart*1000000 << "us" << endl;

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
        cout << "Setupʱ��" << T_init << "us" << endl;
    }

    //����˽Կ ��Կ�������Ի���Կ��֧����ת������Կ
    //ҽԺ������Կ
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
        cout << "HosKeygenʱ��" << (double)(H_keygen_end.QuadPart - H_keygen_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    }
    
    //�û�������Կʱ��
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
        cout<<"PatKeygenʱ��"<< (double)(P_keygen_end.QuadPart - P_keygen_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    }
    /**********************�û���������**********************/
    LARGE_INTEGER User_request_begin, User_request_end;
    QueryPerformanceCounter(&User_request_begin);
    Plaintext pt_x;
    encoder.encode(x, scale, pt_x);
    Ciphertext ct_x;
    encryptor.encrypt(pt_x, ct_x);
    QueryPerformanceCounter(&User_request_end);
    //cout << "�û������Running time: " << (double)(User_request_end.QuadPart - User_request_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    T_request += (double)(User_request_end.QuadPart - User_request_begin.QuadPart) / (double)nFreq.QuadPart * 1000000;

    /**********************�������**********************/
    //ģ��W��b���,���Ծ�̯�����ÿ���
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
        cout << "ModOutʱ��" << (double)(ModOut_end.QuadPart - ModOut_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    }
    //��֤����
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
    //cout << "����׶ε�Running time: " << (double)(Outsource_end.QuadPart - Outsource_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    /**********************����׶�**********************/
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
    //cout << "��ȫ����ֵ�����Running time: " << (double)(Computate_end.QuadPart - Computate_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    T_DFC += (double)(Computate_end.QuadPart - Computate_begin.QuadPart) / (double)nFreq.QuadPart * 1000000;
    /**********************����ֵ��֤**********************/
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
            cout << "��֤ʧ��" << "                 ";
            cout <<"ֱ�Ӽ���ľ���ֵΪ"<<d[i]<<"       " << "����ֵdΪ��" << d2[i] << "     " << "��֤����Ϊ��" << v[i] << endl;
        }
    }
    QueryPerformanceCounter(&Verfiy_end);
    //����������ֵ
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
    //cout << "�����Running time: " << (double)(Verfiy_mid.QuadPart - Verfiy_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    //cout << "��֤��Running time: " << (double)(Verfiy_end.QuadPart - Verfiy_mid.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    //cout<<"�������ֵ��Running time:"<< (double)(find_max_end.QuadPart - Verfiy_end.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
    T_Verify += (double)(Verfiy_end.QuadPart - Verfiy_begin.QuadPart) / (double)nFreq.QuadPart * 1000000;
    T_classification += (double)(find_max_end.QuadPart - Verfiy_end.QuadPart) / (double)nFreq.QuadPart * 1000000;
    //ҽԺʹ�û�����Կ������ϼ����ı�ǩ���͸�����
    LARGE_INTEGER Send_label_begin, Send_label_end;
    QueryPerformanceCounter(&Send_label_begin);
    Plaintext pt_label;
    encoder.encode(label, scale, pt_label);
    Ciphertext ct_label;
    P_encryptor.encrypt(pt_label,ct_label);
    QueryPerformanceCounter(&Send_label_end);
    T_classification += (double)(Send_label_end.QuadPart - Send_label_begin.QuadPart) / (double)nFreq.QuadPart * 1000000;
    //cout << "���ͱ�ǩ�����˵�Running time: " << (double)(Send_label_end.QuadPart - Send_label_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;

    //����ʹ��˽Կ���ܱ�ǩ
    LARGE_INTEGER Get_label_begin, Get_label_end;
    QueryPerformanceCounter(&Get_label_begin);
    Plaintext pt_result;
    P_decryptor.decrypt(ct_label, pt_result);
    vector<double> result;
    encoder.decode(pt_result, result);
    QueryPerformanceCounter(&Get_label_end);
    //cout << "���˵õ���ǩ��Running time: " << (double)(Get_label_end.QuadPart - Get_label_begin.QuadPart) / (double)nFreq.QuadPart * 1000000 << "us" << endl;
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
    cout << "���ǵķ���VMSOD��׼ȷ��Ϊ:" << score << endl;
    //cout << "��ʼ��ʱ�䣺" << T_init << endl;
    
    //cout << "���ݼ���ʱ�䣺" << T_dataencrypt << endl;
    cout << "Computateʱ�䣺" << T_DFC << endl;
    cout << "Queryʱ�䣺" << T_classification << endl;
    cout << "requestʱ��" << T_request << endl;
    cout << "DiaOutʱ��" << T_DiaOut << endl;
    cout << "Decodeʱ��" << T_decode << endl;
    cout << "Verifyʱ��" << T_Verify << endl;
    return 0;
}

