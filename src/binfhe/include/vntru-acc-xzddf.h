//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
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
#ifndef _VNTRU_ACC_XZDDF_H_
#define _VNTRU_ACC_XZDDF_H_

// #include "rgsw-acc.h"
#include "vntru-acc.h"

#include <memory>

using namespace std;
namespace lbcrypto {


class VectorNTRUAccumulatorXZDDF final : public VectorNTRUAccumulator {
public:
    VectorNTRUAccumulatorXZDDF() = default;

    VectorNTRUACCKey KeyGenAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& skNTT,
                         const NativePoly& invskNTT,   ConstLWEPrivateKey& LWEsk) const override;
    void EvalAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params, ConstVectorNTRUACCKey& ek, NTRUCiphertext& acc,
                 const NativeVector& a) const override;

private:

    VectorNTRUEvalKey KDMKeyGenXZDDF(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& invskNTT,
                            LWEPlaintext m) const;
    VectorNTRUEvalKey KeyGenXZDDF(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& invskNTT,
                            LWEPlaintext m) const;                        

    VectorNTRUEvalKey KeyGenAuto(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& skNTT,
    const NativePoly& invskNTT, LWEPlaintext k) const;
    void AddToAccXZDDF(const std::shared_ptr<VectorNTRUCryptoParams>& params, ConstVectorNTRUEvalKey& ek,
                    NTRUCiphertext& acc) const;
    void Automorphism(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativeInteger& a,
                      ConstVectorNTRUEvalKey& ak, NTRUCiphertext& acc) const;
};

}  // namespace lbcrypto

#endif  // _VNTRU_ACC_XZDDF_H_