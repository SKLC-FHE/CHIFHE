//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
 * Custom Modifications:
 * - [This code is the implementation of the algorithm in the paper https://eprint.iacr.org/2023/1564]
 * 
 * This modified section follows the terms of the original BSD 2-Clause License.
 * Other modifications are provided under the terms of the BSD 2-Clause License.
 * See the BSD 2-Clause License text below:
 */


//==================================================================================
// Additional BSD License for Custom Modifications:
//
// Copyright (c) 2023 Binwu Xiang,Kaixing Wang and other contributors
//
// All rights reserved.
//
// Author TPOC: wangkaixing22@mails.ucas.ac.cn
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#include "vntru-acc-xzddf.h"

#include <string>
#include <vector>
namespace lbcrypto {

VectorNTRUACCKey VectorNTRUAccumulatorXZDDF::KeyGenAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                                       const NativePoly& skNTT, const NativePoly& invskNTT,
                                                       ConstLWEPrivateKey& LWEsk) const {
    auto sv{LWEsk->GetElement()};
    auto mod{sv.GetModulus().ConvertToInt<int32_t>()};  //q_ks
    auto modHalf{mod >> 1};
    size_t n{sv.GetLength()};
    auto q{params->Getq().ConvertToInt<size_t>()};
    
    VectorNTRUACCKey ek = std::make_shared<VectorNTRUACCKeyImpl>(1, 2, q - 1 > n + 1 ? q - 1 : n + 1);
    //生成评估秘钥
    auto s{sv[0].ConvertToInt<int32_t>()};                                          // 0 +-1
    (*ek)[0][0][0] = KDMKeyGenXZDDF(params, invskNTT, s > modHalf ? mod - s : -s);  //第一个evk(KDM-form)

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    for (size_t i = 1; i < n; ++i) {
        auto s{sv[i].ConvertToInt<int32_t>()};
        (*ek)[0][0][i] = KeyGenXZDDF(params, invskNTT, s > modHalf ? mod - s : -s);
        //如果s大于modHalf，则返回s - mod，否则返回s
    }
    auto sums = 0;
    for (size_t i = 0; i < n; ++i) {
        auto s{sv[i].ConvertToInt<int32_t>()};
        sums = sums +s;
    }
    sums %= mod;
    if (sums > modHalf) {
        sums -= mod;
    }
    (*ek)[0][0][n] = KeyGenXZDDF(params, invskNTT, sums);
    //生成自同构秘钥
    int64_t intq = params->Getq().ConvertToInt<int64_t>();  
    int64_t N    = params->GetN();
    for (auto i = 0; i < intq - 1; ++i) {
        (*ek)[0][1][i] = KeyGenAuto(params, skNTT, invskNTT, (2 * N / intq) * (i + 1) + 1);
    }
    return ek;
}

void VectorNTRUAccumulatorXZDDF::EvalAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                         ConstVectorNTRUACCKey& ek, NTRUCiphertext& acc, const NativeVector& a) const {
    size_t n   = a.GetLength();
    uint32_t N = params->GetN();
    int32_t q  = params->Getq().ConvertToInt<int32_t>();
    std::vector<uint32_t> ua(n);
    std::vector<uint32_t> w(n);
    std::vector<uint32_t> invw(n + 1);
    invw[n] = 1;
    std::vector<NativeInteger> NATIVEw(n);  //自同构的次数
    std::vector<uint32_t> invindex(n);      //对应到autk 的index

    for (size_t i = 0; i < n; i++) {
        ua[i]   = a[i].ConvertToInt<int32_t>();       //a
        w[i]    = (2 * N / q) * ua[i] + 1;            //w_i
        invw[i] = ModInverse(w[i], 2 * N) % (2 * N);  //w_inv
    }
    for (size_t i = 0; i < n; i++) {
        NATIVEw[i] = NativeVector::Integer((w[i] * invw[i + 1]) % (2 * N));
        invindex[i] = (NATIVEw[i].ConvertToInt<int32_t>() - 2*N/q -1) / ( 2*N/q);
    }
    for (size_t i = 0; i < n; i++) {
        AddToAccXZDDF(params, (*ek)[0][0][i], acc);  ///evk_{0 ~ n-1}
        if (NATIVEw[i].ConvertToInt<int32_t>() != 1) {
            Automorphism(params, NATIVEw[i], (*ek)[0][1][invindex[i]], acc);
        }
    }
   
    AddToAccXZDDF(params, (*ek)[0][0][n], acc);
}

// KDM-form
VectorNTRUEvalKey VectorNTRUAccumulatorXZDDF::KDMKeyGenXZDDF(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                                             const NativePoly& invskNTT, LWEPlaintext m) const {
    auto polyParams = params->GetPolyParams();  //(Q,2N)
    auto Gpow       = params->GetGPower();      //
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};
    dug.SetModulus(Q);  //确保dug的模数是Q
                        //Reduce mod q (dealing with negative number as well)
    int64_t N  = params->GetN();
    int64_t mm = (((m % N) + N) % N);  // 0 1 N-1
    bool isReducedMM{false};
    if (m < 0) {
        isReducedMM = true;
    }
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG2{(params->GetDigitsG() - 1)};
    std::vector<NativePoly> tempA(digitsG2, NativePoly(dug, polyParams, Format::COEFFICIENT));
    VectorNTRUEvalKeyImpl result(digitsG2);
    for (uint32_t i = 0; i < digitsG2; ++i) {
        result[i] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);  //采样g
        if (!isReducedMM)
            result[i][mm].ModAddFastEq(Gpow[i + 1],Q);  // g+X^m*G
        else
            result[i][mm].ModSubFastEq(Gpow[i + 1],Q);  // g-X^m*G
        result[i].SetFormat(Format::EVALUATION);
        result[i] = result[i] * invskNTT;
    }
    return std::make_shared<VectorNTRUEvalKeyImpl>(result);
}
//NO KDM-form
VectorNTRUEvalKey VectorNTRUAccumulatorXZDDF::KeyGenXZDDF(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                                          const NativePoly& invskNTT, LWEPlaintext m) const {
    auto polyParams = params->GetPolyParams();  //(Q,2N)
    auto Gpow       = params->GetGPower();      //
    NativeInteger Q{params->GetQ()};
    int64_t N  = params->GetN();
    int64_t mm = (((m % N) + N) % N);  // 0 1 q-1
    bool isReducedMM{false};
    if (m < 0) {
        isReducedMM = true;
    }
    uint32_t digitsG2{(params->GetDigitsG() - 1)};  //2
    NativePoly zeroPoly(polyParams, Format::COEFFICIENT);
    zeroPoly.SetValuesToZero();
    std::vector<NativePoly> tempA(digitsG2, zeroPoly);

    VectorNTRUEvalKeyImpl result(digitsG2);
    for (uint32_t i = 0; i < digitsG2; ++i) {
        // result[i][0] = tempA[i];
        tempA[i].SetFormat(Format::COEFFICIENT);
        result[i] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);  //采样g
        result[i].SetFormat(Format::EVALUATION);
        result[i] = result[i] * invskNTT;  // g/f
        if (!isReducedMM)
            tempA[i][mm].ModAddFastEq(Gpow[i + 1], Q);  // X^m*G
        else
            tempA[i][mm].ModSubFastEq(Gpow[i + 1], Q);  // X^m*G
        tempA[i].SetFormat(Format::EVALUATION);
        result[i] = result[i] + tempA[i];
    }
    return std::make_shared<VectorNTRUEvalKeyImpl>(result);
}
VectorNTRUEvalKey VectorNTRUAccumulatorXZDDF::KeyGenAuto(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                                         const NativePoly& skNTT, const NativePoly& invskNTT,
                                                         LWEPlaintext k) const {
    //auto polyParams{params->GetPolyParams()};
    // m_polyParams{std::make_shared<ILNativeParams>(2 * N, Q)},
    // auto Gpow{params->GetGPower()};//m_Gpower,是一个3长度vector (0,1024,1048576)
    auto polyParams = params->GetPolyParams();  //(Q,2N)
    auto Gpow       = params->GetGPower();      //

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};
    dug.SetModulus(Q);
    auto skAuto{skNTT.AutomorphismTransform(k)};  //生成f(X^k)

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG{params->GetDigitsG() - 1};
    VectorNTRUEvalKeyImpl result(digitsG);

    for (uint32_t i = 0; i < digitsG; ++i) {
        result[i] = NativePoly(params->GetDgg(), polyParams, EVALUATION) + skAuto * Gpow[i + 1];
        result[i] = result[i] * invskNTT;
    }
    return std::make_shared<VectorNTRUEvalKeyImpl>(result);
}

void VectorNTRUAccumulatorXZDDF::AddToAccXZDDF(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                               ConstVectorNTRUEvalKey& ek, NTRUCiphertext& acc) const {
    NativePoly ct(acc->GetElements());
    ct.SetFormat(Format::COEFFICIENT);
    
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG{(params->GetDigitsG() - 1)};
    std::vector<NativePoly> dct(digitsG,
                                NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));  // d-1维N长多项式
    SignedDigitDecompose(params, ct, dct);                                                        //分解acc
    // calls digitsG2 NTTs
    NativePoly sum(params->GetPolyParams(), Format::EVALUATION, true);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsG))
    for (uint32_t d = 0; d < digitsG; ++d)
        dct[d].SetFormat(Format::EVALUATION);
    // acc = dct * ek (matrix product);
    const std::vector<NativePoly>& ev = ek->GetElements();
    for (uint32_t d = 0; d < digitsG; ++d)
        sum += (dct[d] *= ev[d]);

    acc->GetElements() = sum;
}

void VectorNTRUAccumulatorXZDDF::Automorphism(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                              const NativeInteger& a, ConstVectorNTRUEvalKey& ak,
                                              NTRUCiphertext& acc) const {
    // precompute bit reversal for the automorphism into vec
    uint32_t N{params->GetN()};
    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, a.ConvertToInt<usint>(), &vec);  //
    NativePoly ct(acc->GetElements());
    acc->GetElements().SetValuesToZero();
    ct = ct.AutomorphismTransform(a.ConvertToInt<usint>(), vec);
    ct.SetFormat(COEFFICIENT);
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG{params->GetDigitsG() - 1};
    std::vector<NativePoly> dct(digitsG, NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));
    SignedDigitDecompose(params, ct, dct);
    NativePoly sum(params->GetPolyParams(), Format::EVALUATION, true);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsG))
    for (uint32_t d = 0; d < digitsG; ++d)
        dct[d].SetFormat(Format::EVALUATION);
    // acc = dct * input (matrix product);
    const std::vector<NativePoly>& ev = ak->GetElements();
    for (uint32_t d = 0; d < digitsG; ++d)
        sum += (dct[d] * ev[d]);

    acc->GetElements() = sum;
}

};  // namespace lbcrypto